package main

// testRef names a Go test function: Pkg is the directory from the repository
// root, Name the function. The package test checks that it exists.
type testRef struct{ Pkg, Name string }

// rule is one statement the manual makes about what `chap` or `chapd` will and
// will not do. Covers lists exact phrases of the generated manual that this
// rule justifies; every line of the manual that says "never" must hold one.
type rule struct {
	Text   string
	Where  string
	Tests  []testRef
	Covers []string
}

// rules is the table printed at the end of the manual. Add a row here before
// putting a "never" (or any hard promise) in intro.md or in chap's help text.
var rules = []rule{
	{
		Text:  "`chap` takes its credential from `CHAP_RUN_TOKEN`, else the orchestrator token file. No flag accepts a token or any other secret.",
		Where: "cmd/chap: `loadToken`, and every flag set",
		Tests: []testRef{{"cmd/chap", "TestNoFlagAcceptsASecret"}, {"cmd/chap", "TestTokenPrecedence"}, {"docs/manualgen", "TestNoFlagNamesACredential"}},
	},
	{
		Text:  "`chap` sends its token only to a loopback `chapd`: a `CHAP_URL` anywhere else is refused, and a redirect is not followed.",
		Where: "cmd/chap: `baseURL`, the HTTP client's `CheckRedirect`",
		Tests: []testRef{{"cmd/chap", "TestBaseURL"}, {"cmd/chap", "TestRedirectIsNotFollowed"}},
	},
	{
		Text:  "Everything `chap` prints is masked: the token in use, and anything shaped like an orchestrator token, a JWT, a GitHub or API key or a PEM block. A request or denial that holds a registered secret is refused by `chapd` (`REDACTION_BLOCKED`) before it is stored or echoed.",
		Where: "cmd/chap: `app.scrub`; internal/redact; internal/ops: `submissionLeaks`",
		Tests: []testRef{{"cmd/chap", "TestScrubMasksSecretShapes"}, {"test/redteam", "TestRT26CanaryNeverAppearsAnywhere"}, {"test/redteam", "TestRT26AgentSuppliedSecret"}},
	},
	{
		Text:   "`chap dev-token` writes the token it mints to a new file and prints nothing of it. It creates the file exclusively, so an existing file is refused, not overwritten. The file is private to you from the moment it exists: mode 0600 where the system has file modes, and on Windows, where the mode means nothing, a protected access list for your user alone that is given in the same call that creates the file, so it does not take the access of its folder. A link at the path is refused, not followed.",
		Where:  "cmd/chap: `createPrivateFile`, `cmdDevToken`; internal/privfile: `Create`",
		Tests:  []testRef{{"cmd/chap", "TestDevTokenWritesFileOnly"}, {"cmd/chap", "TestKeyFilesArePrivateFromCreation"}, {"internal/privfile", "TestCreateIsOwnerOnlyByIcacls"}, {"internal/privfile", "TestCreateIsMode0600"}, {"internal/privfile", "TestCreateDoesNotFollowALink"}},
		Covers: []string{"never overwritten"},
	},
	{
		Text:   "`chap vault status` shows secret names and counts only. No chapd route, `chap` command or ledger field returns a secret value; the vault's only reader is `Vault.Use`, which hands the value to one adapter closure.",
		Where:  "internal/vault: `Use`; internal/ops: the vault status route",
		Tests:  []testRef{{"internal/vault", "TestNoFunctionReturnsASecret"}, {"test/redteam", "TestRT26CanaryNeverAppearsAnywhere"}},
		Covers: []string{"never a value"},
	},
	{
		Text:   "The `--reason` text is for the approver to read. The card shows it in a box labelled as written by the requester and untrusted, and it is recorded. It is not part of the op hash an approval binds to, and no policy or adapter code reads it.",
		Where:  "internal/spec: `OpHash`; internal/approvals: `card.go`",
		Tests:  []testRef{{"docs/manualgen", "TestReasonIsNotPartOfTheOpHash"}, {"docs/manualgen", "TestNoAdapterOrPolicyReadsTheReason"}},
		Covers: []string{"never used for authorization"},
	},
	{
		Text:  "A high or critical op always needs one approval bound to the exact request (`OP_APPROVAL_REQUIRED` until it is approved); a changed parameter is a new card (`APPROVAL_HASH_MISMATCH`).",
		Where: "internal/ops: `service.go` (`Class.NeedsApproval`); internal/approvals",
		Tests: []testRef{{"internal/ops", "TestApprovalFlow"}, {"test/redteam", "TestRT24DemoEmail"}},
	},
	{
		Text:  "`chap` cannot approve. It has no approve verb, and `chapd` has no API route or verb that decides an approval: that takes a user-verified WebAuthn assertion in the console.",
		Where: "cmd/chap: the command table; internal/ops: the route table; internal/approvals: `Approve`",
		Tests: []testRef{{"docs/manualgen", "TestChapHasNoApproveVerb"}, {"test/redteam", "TestRT13ApprovalCannotBeDecidedOverTheAPI"}},
	},
	{
		Text:  "An op that policy has not enabled is refused with `OP_DISABLED`, for a run and for the orchestrator.",
		Where: "internal/ops: `Service.Submit`; internal/policy: `Effective.Enabled`",
		Tests: []testRef{{"internal/ops", "TestOpDisabledByDefault"}},
	},
	{
		Text:  "The Linear intake (`chap intake`) writes two things only: a comment, and a move to a state the project's policy lists. It writes only to an item of the one policy team that carries the policy label at the moment of the write (`chapd` reads it again just before), never to the Engineering team, and it cannot remove or add a label, edit a title or description, assign, archive or delete: `chapd` sends five fixed GraphQL documents and the caller supplies no query.",
		Where: "internal/connectors/linear: `queries.go`, `base.guard`, `moveAdapter`",
		Tests: []testRef{
			{"internal/connectors/linear", "TestOnlyTheFiveFixedDocumentsAreEverSent"},
			{"internal/connectors/linear", "TestTheDocumentsCannotChangeLabelsTextOrDelete"},
			{"internal/connectors/linear", "TestLabelRemovedBetweenCheckAndWriteStopsTheComment"},
			{"internal/connectors/linear", "TestLabelRemovedBetweenCheckAndWriteStopsTheMove"},
			{"internal/connectors/linear", "TestATeamCalledEngineeringIsNeverWrittenTo"},
			{"internal/connectors/linear", "TestMoveToAStateThePolicyDoesNotListIsRefused"},
		},
		Covers: []string{"never to the Engineering team"},
	},
	{
		Text:  "`chap mcp` serves the ops as MCP tools to a client on the same machine over stdio, and does nothing the command line cannot: each tool call is one request to `chapd` with the same credential, so policy, approvals and the ledger apply. It listens on nothing, and it cannot show or change an approval card: a call that needs a human returns only the op id, the approval id, the class and the time left. Text an op read from outside comes back in a field named `untrusted_result`.",
		Where: "internal/mcpfront; cmd/chap: `mcp.go`",
		Tests: []testRef{
			{"internal/mcpfront", "TestPackageImportsOnlyWhatItMay"},
			{"internal/mcpfront", "TestPendingResultHasOnlyFixedFields"},
			{"internal/mcpfront", "TestAllowedCallAndInjectedTextStaysData"},
			{"cmd/chap", "TestMcpTranscriptBothEras"},
		},
	},
}
