package mobile

import (
	"regexp"
	"strconv"
	"strings"
)

// dumpsys activity top asks the activity process to dump its native views,
// without registering another UiAutomation service. A dump failure alone does
// not identify which instrumentation, service or ROM component holds a slot.
//
// Each view line looks like:
//
//	ClassName{hash V.ED..... ......ID L,T-R,B #idhex pkg:id/name}
//
// where L,T-R,B are the view's bounds RELATIVE to its parent. Absolute screen
// coordinates are estimated by summing ancestor offsets. The dump does not
// expose scroll positions, transforms or screen window origins, so these are
// approximate and must be checked against a screenshot before use.
var dumpsysViewRE = regexp.MustCompile(`^(\s*)([\w.$]+)\{[0-9a-fA-F]+\s+(\S+)\s+(\S+)\s+(-?\d+),(-?\d+)-(-?\d+),(-?\d+)(?:\s+#[0-9a-fA-F]+\s+([^\s}]+))?`)

type dumpsysFrame struct {
	indent  int
	absX    int
	absY    int
	visible bool
}

// parseDumpsysTop flattens `dumpsys activity top` output into elements with
// estimated coordinates. interactableOnly keeps visible nodes that carry a
// resource id or clickable flag; a full flatten is used for
// locator matching. Text/content-desc are not exposed by dumpsys, so locating
// by resource id is the reliable path with this source.
func parseDumpsysTop(data []byte, interactableOnly bool) []Element {
	out := make([]Element, 0)
	var stack []dumpsysFrame
	var pkg string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ACTIVITY ") {
			stack = nil
			pkg = ""
			fields := strings.Fields(trimmed)
			if len(fields) > 1 {
				pkg = strings.SplitN(fields[1], "/", 2)[0]
			}
		}
		if trimmed == "View Hierarchy:" {
			stack = nil
		}
		m := dumpsysViewRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		indent := len(m[1])
		flags := m[3]
		privateFlags := m[4]
		left := atoi(m[5])
		top := atoi(m[6])
		right := atoi(m[7])
		bottom := atoi(m[8])
		resID := m[9]

		// Parent is the nearest frame with a smaller indent.
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		var px, py int
		parentVisible := true
		if len(stack) > 0 {
			px, py = stack[len(stack)-1].absX, stack[len(stack)-1].absY
			parentVisible = stack[len(stack)-1].visible
		}
		absX, absY := px+left, py+top
		visible := parentVisible && len(flags) > 0 && flags[0] == 'V'
		stack = append(stack, dumpsysFrame{indent: indent, absX: absX, absY: absY, visible: visible})
		width, height := right-left, bottom-top
		if !visible || width <= 0 || height <= 0 {
			continue
		}
		clickable := len(flags) > 6 && flags[6] == 'C'
		if interactableOnly && resID == "" && !clickable {
			continue
		}
		el := Element{
			Class:      m[2],
			Package:    pkg,
			ResourceID: resID,
			Clickable:  clickable,
			Focused:    len(privateFlags) > 1 && privateFlags[1] == 'F',
			Bounds:     "[" + itoa(absX) + "," + itoa(absY) + "][" + itoa(absX+width) + "," + itoa(absY+height) + "]",
			X:          absX + width/2,
			Y:          absY + height/2,
			Width:      width,
			Height:     height,
		}
		el.Index = len(out)
		out = append(out, el)
	}
	return out
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
func itoa(n int) string { return strconv.Itoa(n) }
