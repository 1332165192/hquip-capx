package mobile

import (
	"encoding/xml"
	"regexp"
	"strconv"
	"strings"
)

// Element is one node from the accessibility tree, flattened and enriched with a
// tap point so the caller can click by index without re-parsing bounds.
type Element struct {
	Index      int    `json:"index"`
	Class      string `json:"class,omitempty"`
	Package    string `json:"package,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
	Text       string `json:"text,omitempty"`
	Desc       string `json:"content_desc,omitempty"`
	Clickable  bool   `json:"clickable"`
	Scrollable bool   `json:"scrollable"`
	Focused    bool   `json:"focused"`
	Bounds     string `json:"bounds,omitempty"`
	X          int    `json:"x"`
	Y          int    `json:"y"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
}

type xmlNode struct {
	Text        string    `xml:"text,attr"`
	ResourceID  string    `xml:"resource-id,attr"`
	Class       string    `xml:"class,attr"`
	Package     string    `xml:"package,attr"`
	ContentDesc string    `xml:"content-desc,attr"`
	Clickable   string    `xml:"clickable,attr"`
	Scrollable  string    `xml:"scrollable,attr"`
	Focused     string    `xml:"focused,attr"`
	Bounds      string    `xml:"bounds,attr"`
	Nodes       []xmlNode `xml:"node"`
}

type xmlHierarchy struct {
	XMLName xml.Name  `xml:"hierarchy"`
	Nodes   []xmlNode `xml:"node"`
}

var boundsRE = regexp.MustCompile(`\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]`)

// parseUIDump flattens a `uiautomator dump` document. When interactableOnly is
// set only nodes carrying text, a content description, a resource id, or a
// clickable/scrollable flag are returned — the useful surface for automation —
// while a full flatten (interactableOnly=false) is used for locator matching.
func parseUIDump(data []byte, interactableOnly bool) ([]Element, error) {
	var h xmlHierarchy
	if err := xml.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	out := make([]Element, 0)
	var walk func(n xmlNode)
	walk = func(n xmlNode) {
		el := Element{
			Class:      n.Class,
			Package:    n.Package,
			ResourceID: n.ResourceID,
			Text:       strings.TrimSpace(n.Text),
			Desc:       strings.TrimSpace(n.ContentDesc),
			Clickable:  n.Clickable == "true",
			Scrollable: n.Scrollable == "true",
			Focused:    n.Focused == "true",
			Bounds:     n.Bounds,
		}
		if m := boundsRE.FindStringSubmatch(n.Bounds); m != nil {
			x1, _ := strconv.Atoi(m[1])
			y1, _ := strconv.Atoi(m[2])
			x2, _ := strconv.Atoi(m[3])
			y2, _ := strconv.Atoi(m[4])
			el.X, el.Y = (x1+x2)/2, (y1+y2)/2
			el.Width, el.Height = x2-x1, y2-y1
		}
		keep := !interactableOnly || el.Clickable || el.Scrollable ||
			el.Text != "" || el.Desc != "" || el.ResourceID != ""
		if keep {
			el.Index = len(out)
			out = append(out, el)
		}
		for _, child := range n.Nodes {
			walk(child)
		}
	}
	for _, n := range h.Nodes {
		walk(n)
	}
	return out, nil
}

// Locator selects an element for a click. Fields are ANDed; an empty locator
// matches nothing. Partial makes text/desc matching a substring test.
type Locator struct {
	Text       string `json:"text"`
	ResourceID string `json:"resource_id"`
	Desc       string `json:"content_desc"`
	Partial    bool   `json:"partial"`
}

func (l Locator) empty() bool {
	return strings.TrimSpace(l.Text) == "" &&
		strings.TrimSpace(l.ResourceID) == "" &&
		strings.TrimSpace(l.Desc) == ""
}

func (l Locator) matches(e Element) bool {
	if l.empty() {
		return false
	}
	match := func(want, got string) bool {
		want = strings.TrimSpace(want)
		if want == "" {
			return true
		}
		if l.Partial {
			return strings.Contains(got, want)
		}
		return got == want
	}
	if !match(l.Text, e.Text) || !match(l.Desc, e.Desc) {
		return false
	}
	if rid := strings.TrimSpace(l.ResourceID); rid != "" {
		got := e.ResourceID
		if strings.HasPrefix(got, "app:") && e.Package != "" && strings.HasPrefix(rid, e.Package+":") {
			got = e.Package + strings.TrimPrefix(got, "app")
		}
		// Accept a short entry name, but never confuse search with search_btn.
		if !strings.Contains(rid, ":") {
			if i := strings.LastIndex(got, "/"); i >= 0 {
				got = got[i+1:]
			}
		}
		if got != rid {
			return false
		}
	}
	return true
}
