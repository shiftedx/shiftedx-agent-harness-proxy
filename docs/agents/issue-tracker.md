# Issue tracker: GitHub

Issues, specs, and tickets live in GitHub Issues. Use the `gh` CLI.

## Repository binding

Infer the repository from its GitHub `origin` remote. If no GitHub remote exists, stop before
creating or modifying issues and ask the owner to bind the repository.

## Operations

- Create: `gh issue create --title "..." --body "..."`
- Read: `gh issue view <number> --comments`
- List: `gh issue list --state open --json number,title,body,labels,comments`
- Comment: `gh issue comment <number> --body "..."`
- Label: `gh issue edit <number> --add-label "..."`
- Close: `gh issue close <number> --comment "..."`

Use a heredoc for multiline issue bodies.

## Pull requests as a triage surface

**PRs as a request surface: no.**

A bare `#42` may be an issue or pull request. Try `gh pr view 42`, then fall back to
`gh issue view 42`.

## Skill terminology

- “Publish to the issue tracker” means create a GitHub issue.
- “Fetch the relevant ticket” means read the issue and its comments.
- Prefer native GitHub sub-issues and dependencies for parent and blocking relationships.

## Wayfinding

A wayfinding map is an issue labelled `wayfinder:map`; its tickets are child issues.

- Label children `wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or
  `wayfinder:task`.
- Claim a ticket by assigning it to the driving developer.
- Prefer GitHub’s native issue dependencies for blocking edges.
- An unassigned open child with no open blocker is on the frontier.
- Resolve a ticket by recording its answer, closing it, and linking the decision from the map.
