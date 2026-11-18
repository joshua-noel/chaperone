package google

import (
	"context"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/google/googletest"
	"github.com/joshua-noel/chaperone/internal/ops"
)

const fileID = "1AbCdEfGhIjKlMnOpQrS"

func driveRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t, true)
	r.fake.AddFile(googletest.File{ID: fileID, Name: "Q3 plan", MimeType: "application/vnd.google-apps.document", CanShare: true})
	return r
}

func shareParams() map[string]any {
	return map[string]any{"file_id": fileID, "file_name": "Q3 plan", "recipients": []any{"gilliano@example.com"}, "role": "reader", "link_visibility": "restricted"}
}

func shareReq(p map[string]any) *ops.Request {
	return req("drive.share", "google", "operator@example.com", p)
}

func TestDriveShareHappyPath(t *testing.T) {
	r := driveRig(t)
	ctx := context.Background()
	p := shareParams()
	p["role"] = "commenter" // the cap, inclusive
	cr, err := r.drive.Check(ctx, shareReq(p))
	if err != nil {
		t.Fatal(err)
	}
	ev := cr.Evidence[0].Text
	for _, want := range []string{"Q3 plan", fileID, "commenter", "restricted", "No notification"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence lacks %q:\n%s", want, ev)
		}
	}
	out, err := r.drive.Execute(ctx, shareReq(p))
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("%+v %v", out, err)
	}
	perms := r.fake.Permissions()
	if len(perms) != 1 || perms[0].Email != "gilliano@example.com" || perms[0].Role != "commenter" || perms[0].Type != "user" || perms[0].Notify {
		t.Fatalf("permissions: %+v", perms)
	}
	if out.ExternalRef != "gdrive:file/"+fileID {
		t.Errorf("ref %q", out.ExternalRef)
	}
}

func TestDriveShareRefusals(t *testing.T) {
	r := driveRig(t)
	r.fake.AddFile(googletest.File{ID: "BinnedFile0123456789", Name: "Old", Trashed: true, CanShare: true})
	r.fake.AddFile(googletest.File{ID: "NotMine01234567890", Name: "Theirs", CanShare: false})
	ctx := context.Background()
	cases := []struct {
		name string
		mut  func(p map[string]any)
		code string
		why  string
	}{
		{"recipient off the list", func(p map[string]any) { p["recipients"] = []any{"attacker@example.net"} }, "OP_POLICY_REFUSED", "allowlist"},
		{"domain entries are for mail only here", func(p map[string]any) { p["recipients"] = []any{"x@acme.example"} }, "OP_POLICY_REFUSED", "allowlist"},
		{"writer is above the cap", func(p map[string]any) { p["role"] = "writer" }, "OP_POLICY_REFUSED", "cap"},
		{"owner is never allowed", func(p map[string]any) { p["role"] = "owner" }, "OP_PARAMS_INVALID", "owner"},
		{"organizer is never allowed", func(p map[string]any) { p["role"] = "organizer" }, "OP_PARAMS_INVALID", "role"},
		{"anyone with the link", func(p map[string]any) { p["link_visibility"] = "anyone" }, "OP_PARAMS_INVALID", "named people"},
		{"visibility missing", func(p map[string]any) { delete(p, "link_visibility") }, "OP_PARAMS_INVALID", "link_visibility"},
		{"name that is not Drive's", func(p map[string]any) { p["file_name"] = "Public holiday rota" }, "OP_PARAMS_INVALID", "not the file's name"},
		{"no such file", func(p map[string]any) { p["file_id"] = "Nope0123456789ABCDEF" }, "OP_PARAMS_INVALID", "no file"},
		{"file id with a path", func(p map[string]any) { p["file_id"] = "../../about" }, "OP_PARAMS_INVALID", "not a Drive file id"},
		{"trashed", func(p map[string]any) { p["file_id"], p["file_name"] = "BinnedFile0123456789", "Old" }, "OP_PARAMS_INVALID", "bin"},
		{"cannot share", func(p map[string]any) { p["file_id"], p["file_name"] = "NotMine01234567890", "Theirs" }, "OP_POLICY_REFUSED", "may not share"},
		{"too many recipients", func(p map[string]any) {
			p["recipients"] = []any{"a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com", "f@example.com"}
		}, "OP_PARAMS_INVALID", "1 to"},
		{"unknown param", func(p map[string]any) { p["notify_message"] = "click here" }, "OP_PARAMS_INVALID", "unknown param"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := shareParams()
			c.mut(p)
			_, err := r.drive.Check(ctx, shareReq(p))
			ref := wantRefusal(t, err, c.code)
			if !strings.Contains(ref.Why, c.why) {
				t.Errorf("why %q lacks %q", ref.Why, c.why)
			}
		})
	}
	if n := len(r.fake.Permissions()); n != 0 {
		t.Fatalf("%d permissions created", n)
	}
}

func TestDriveRoleCapDefaultsToReader(t *testing.T) {
	r := driveRig(t)
	r.pol.Drive.MaxRole = ""
	p := shareParams()
	p["role"] = "commenter"
	_, err := r.drive.Check(context.Background(), shareReq(p))
	wantRefusal(t, err, "OP_POLICY_REFUSED")
	p["role"] = "reader"
	if _, err := r.drive.Check(context.Background(), shareReq(p)); err != nil {
		t.Fatal(err)
	}
}

func TestDriveNeedsTheDriveScopeAndABlock(t *testing.T) {
	r := newRig(t, true, ScopeGmailSend)
	_, err := r.drive.Check(context.Background(), shareReq(shareParams()))
	ref := wantRefusal(t, err, "OP_POLICY_REFUSED")
	if !strings.Contains(ref.Why, "Drive scope") {
		t.Error(ref.Why)
	}
	r2 := driveRig(t)
	rq := shareReq(shareParams())
	rq.Project = "other-shop"
	_, err = r2.drive.Check(context.Background(), rq)
	wantRefusal(t, err, "OP_POLICY_REFUSED")
}

func TestDriveReleaseRechecksAndNeverRetriesAnUnknown(t *testing.T) {
	r := driveRig(t)
	ctx := context.Background()
	rq := shareReq(shareParams())
	r.pol.Drive.AllowRecipients = []string{"someone-else@example.com"}
	out, _ := r.drive.Execute(ctx, rq)
	if !out.Failed || len(r.fake.Permissions()) != 0 {
		t.Fatalf("%+v", out)
	}
	r.pol.Drive.AllowRecipients = []string{"gilliano@example.com"}
	r.fake.RevokeAll()
	r.fake.ExpireAccess()
	out, _ = r.drive.Execute(ctx, rq)
	if !out.Failed || r.alerts.count(AlertReauth) != 1 {
		t.Fatalf("%+v %v", out, r.alerts.keys)
	}
}
