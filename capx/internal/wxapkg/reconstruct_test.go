package wxapkg

import (
	"strings"
	"testing"
)

func TestReconstructCompleteModuleLexicalBoundaries(t *testing.T) {
	for name, body := range map[string]string{
		"regex brace":      `const r=/}/; module.exports={complete:true};`,
		"regex class":      `const r=/[}/\]]/g; module.exports=42;`,
		"control regex":    `if(ok) /}/.test("}"); module.exports=42;`,
		"division":         `const n = (8+4)/2; module.exports=n/3;`,
		"comments":         "// } ignored\n/* { ignored */module.exports={complete:true};",
		"nested templates": "const x=`outer ${ {value:`inner ${/}/.source}`}.value }`; module.exports=x;",
		"escaped strings":  `const x="\\\"}"; module.exports=x;`,
	} {
		t.Run(name, func(t *testing.T) {
			src := `define("pages/index.js", function(require,module,exports){` + body + `});`
			files := splitDefines(src)
			if len(files) != 1 || files[0].Name != "/pages/index.js" || string(files[0].Data) != body {
				t.Fatalf("module source must stay complete: %#v, expected %q", files, body)
			}
		})
	}
}

func TestReconstructIgnoresFakeCallsAndMalformedWrappers(t *testing.T) {
	for name, src := range map[string]string{
		"string":          `var example="define('fake.js',function(){fake()})";`,
		"comment":         `/* define("fake.js", function(){fake()}); */`,
		"regex":           `const pattern=/define\("fake.js",function\(\){fake\(\)}/;`,
		"template":        "const example=`define(\"fake.js\",function(){fake()})`;",
		"prefix":          `redefine("fake.js",function(){fake()});`,
		"member":          `someObject.define("fake.js",function(){fake()});`,
		"dynamic":         `define("fake.js", construct({notAFunction:true}));`,
		"unclosed body":   `define("fake.js",function(){`,
		"unclosed call":   `define("fake.js",function(){doWork();}`,
		"unclosed string": `define("fake.js",function(){ const x="unterminated; });`,
		"unclosed array":  `define("fake.js",function(){const x=[1,2;});`,
	} {
		t.Run(name, func(t *testing.T) {
			if files := splitDefines(src); len(files) != 0 {
				t.Fatalf("invented module: %#v", files)
			}
		})
	}
	// A damaged tail must not discard an earlier complete wrapper.
	files, notes := Reconstruct([]File{{Name: "/app-service.js", Data: []byte(`define("real.js",function(){module.exports=42;}); define("broken.js",function(){`)}})
	if len(files) != 1 || files[0].Name != "/real.js" {
		t.Fatalf("lost complete module: %#v", files)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "跳过") {
		t.Fatalf("missing incomplete reconstruction note: %v", notes)
	}
}

func TestReconstructWXSSPathBelongsToOwnCall(t *testing.T) {
	// The first call used to take the second call's path and win duplicate-path
	// handling in the desktop archive, exporting the wrong CSS for b.wxss.
	src := `setCssToHead([".a{color:red}"]); setCssToHead([".b{width:",[0,750],";color:blue}"],undefined,{path:"./b.wxss"});`
	files := extractWXSS(src)
	if len(files) != 1 || files[0].Name != "/b.wxss" || string(files[0].Data) != ".b{width:750rpx;color:blue}" {
		t.Fatalf("cross-call CSS provenance: %#v", files)
	}
	for name, src := range map[string]string{
		"opcode":         `setCssToHead([".a{",[2,0],"}"],undefined,{path:"bad.wxss"});`,
		"dynamic path":   `setCssToHead([".a{color:red}"],undefined,{path:"bad.wxss"+suffix});`,
		"dynamic CSS":    `setCssToHead([".a{",getCss(),"}"],undefined,{path:"bad.wxss"});`,
		"unclosed array": `setCssToHead([".a{color:red}",undefined,{path:"bad.wxss"});`,
		"string":         `var x="setCssToHead(['.a{}'], undefined, {path:'fake.wxss'})";`,
		"comment":        `/* setCssToHead([".a{}"],undefined,{path:"fake.wxss"}); */`,
	} {
		t.Run(name, func(t *testing.T) {
			if files := extractWXSS(src); len(files) != 0 {
				t.Fatalf("invented CSS: %#v", files)
			}
		})
	}
}

func TestReconstructWXSSStringEscapes(t *testing.T) {
	src := `setCssToHead(['.a{content:"\\n";background:url("\x61.svg");font-family:"\u4E2D\u6587";}'],undefined,{'path':'escaped.wxss'});`
	files := extractWXSS(src)
	want := ".a{content:\"\\n\";background:url(\"a.svg\");font-family:\"中文\";}"
	if len(files) != 1 || string(files[0].Data) != want {
		t.Fatalf("JS escape order corrupted CSS: %#v, expected %q", files, want)
	}
	decoded, ok := decodeJSString(`"\uD83D\uDE00"`)
	if !ok || decoded != "😀" {
		t.Fatalf("surrogate pair: %q, %v", decoded, ok)
	}
	decoded, ok = decodeJSString("'first\\\r\nsecond'")
	if !ok || decoded != "firstsecond" {
		t.Fatalf("CRLF continuation: %q, %v", decoded, ok)
	}
}

func TestReconstructBoundsMalformedNestingAndKeepsWXMLHonest(t *testing.T) {
	deep := `define("deep.js",function(){` + strings.Repeat("{", 200) + strings.Repeat("}", 200) + `});`
	files, notes := Reconstruct([]File{{Name: "/app-service.js", Data: []byte(deep)}, {Name: "/page-frame.js", Data: []byte(`var $gwx=function(){return {tag:"view"};};`)}})
	if len(files) != 0 {
		t.Fatalf("unsupported nesting exported: %#v", files)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "编译 WXML 未还原") || !strings.Contains(joined, "不执行") {
		t.Fatalf("missing honest WXML limitation: %v", notes)
	}
}
