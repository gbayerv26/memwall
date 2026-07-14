# memwall launch checklist

Name check done 2026-07-14: `memwall` is AVAILABLE on PyPI. No significant
GitHub collision. Move before someone else names the category.

## 0. Prerequisites (one-time)

- [ ] GitHub account ready; decide the repo will be `github.com/gbayerv26/memwall`
- [ ] PyPI account at pypi.org with 2FA enabled
- [ ] PyPI API token created (Account settings -> API tokens, scope: entire account
      for the first upload; switch to a project-scoped token after)

## 1. Final local check

```powershell
cd "C:\Users\Gary\Desktop\claude\new app\memwall"
python -m unittest discover -s tests -t . -v
```

Expect: 30 tests, OK.

## 2. Placeholders and project URLs — DONE

All placeholders are filled with `gbayerv26` / ggbayervaldivia@gmail.com
(README badges and clone URLs, SECURITY.md contact, CONTRIBUTING.md, launch
copy), and `[project.urls]` + the author email are already in pyproject.toml.
Nothing to do here.

## 3. First commit and tag

```powershell
git add .
git commit -m "memwall v0.4.0: scanner + MCP quarantine gateway for agent memory poisoning"
git tag v0.4.0
```

Optional: delete or keep this `launch/` folder in the public repo — your call.

## 4. Create the GitHub repo and push

```powershell
gh repo create memwall --public --source . --push
```

(or create it in the web UI, then `git remote add origin ... ; git push -u origin master --tags`)

Repo settings:
- Description: `Antivirus for AI agent memory — scanner + MCP firewall for memory poisoning (OWASP ASI06)`
- Topics: `ai-agents`, `security`, `mcp`, `memory-poisoning`, `prompt-injection`,
  `llm-security`, `model-context-protocol`, `claude`

## 5. Publish to PyPI

```powershell
python -m pip install --upgrade build twine
python -m build
python -m twine upload dist\*
```

Verify from a clean shell:

```powershell
pip install memwall
memwall rules
```

## 6. Announce (copy lives in this folder)

Order and timing:
- [ ] Show HN (`show_hn.md`) — post Tue-Thu, 8-10am US Eastern. Stay at the
      keyboard for 3 hours to answer every comment; that is most of the outcome.
- [ ] X thread (`social.md`) — same morning, link the HN thread once it has traction.
- [ ] Reddit (`social.md`) — r/AI_Agents and r/LocalLLaMA, next day (staggering avoids
      looking spammy and gives two news cycles).
- [ ] LinkedIn (`social.md`) — same day as Reddit.
- [ ] Blog post (`blog_post.md`) — publish on dev.to or a personal blog first so
      HN/X have somewhere deeper to click through to.

## 7. First week after launch

- [ ] Answer every issue and comment fast — early responsiveness is the moat
- [ ] Open GitHub issues yourself for the roadmap (Zep/Letta/LangGraph adapters,
      policy packs, Phase 3 hosted monitoring) so contributors see direction
- [ ] Note every "this flagged something real" report — those are your future
      case studies and the seed of the hosted product's waitlist
