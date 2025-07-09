# Contributing to DNS Guardian

First off, thank you for considering contributing to DNS Guardian! 🎉

## 📋 Important: Contributor License Agreement (CLA)

**Before we can accept your contributions**, you must agree to our Contributor License Agreement (CLA). This is necessary because DNS Guardian is dual-licensed (AGPL-3.0 + Commercial).

### Why a CLA?

The CLA allows us to:
- Offer DNS Guardian under a commercial license to sustain development
- Protect the project legally
- Ensure all contributions can be included in both open source and commercial versions

### How to Sign

When you submit your first pull request, a bot will automatically ask you to sign the CLA by commenting:

```
I have read the CLA Document and I hereby sign the CLA
```

## 🚀 Getting Started

### Prerequisites

- Go 1.21 or later
- macOS (primary development platform)
- Basic understanding of DNS and TLS/SSL

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/yourusername/dns-guardian.git
   cd dns-guardian
   ```

3. Install dependencies:
   ```bash
   make deps
   ```

4. Build the project:
   ```bash
   make build
   ```

5. Run tests:
   ```bash
   make test
   ```

## 🔧 Development Workflow

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards

3. Format your code:
   ```bash
   make fmt
   ```

4. Test your changes:
   ```bash
   make test
   make run  # Manual testing
   ```

5. Commit with a descriptive message:
   ```bash
   git commit -m "feat: Add support for X"
   ```

6. Push and create a pull request

## 📝 Coding Standards

### Go Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting (run `make fmt`)
- Keep functions small and focused
- Write descriptive variable names
- Add comments for exported functions

### Commit Messages

Follow conventional commits format:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Test additions or modifications
- `chore:` Maintenance tasks

Examples:
```
feat: Add DNS-over-HTTPS support
fix: Resolve certificate caching issue
docs: Update installation instructions
```

### Code Comments

- Document why, not what
- Keep comments up-to-date
- Use complete sentences
- No personal information in comments

## 🧪 Testing

Currently, DNS Guardian has limited automated tests. We welcome contributions to improve test coverage!

### Manual Testing

1. Test DNS blocking:
   ```bash
   make run
   dig @127.0.0.1 doubleclick.net
   ```

2. Test HTTPS interception:
   ```bash
   curl -I https://doubleclick.net
   ```

3. Test configuration changes

### Adding Tests

Place tests in `*_test.go` files following Go conventions. Focus on:
- Unit tests for individual functions
- Integration tests for major features
- Edge cases and error conditions

## 📚 Documentation

- Update README.md for user-facing changes
- Update code comments for implementation changes
- Add entries to docs/ for new features
- Include examples where helpful

## 🐛 Reporting Issues

### Security Issues

For security vulnerabilities:
1. **DO NOT** open a public issue
2. Use GitHub's private security advisory feature
3. Include detailed steps to reproduce

### Bug Reports

Include:
- DNS Guardian version
- macOS version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

### Feature Requests

- Explain the use case
- Describe the desired behavior
- Consider implementation approach

## 💡 Pull Request Process

1. **Small PRs**: Keep changes focused and reviewable
2. **One Feature**: One feature/fix per PR
3. **Tests**: Include tests if possible
4. **Documentation**: Update docs as needed
5. **CLA**: Ensure you've signed the CLA
6. **CI**: Ensure all checks pass

### PR Title Format

Use the same format as commit messages:
```
feat: Add DNS-over-HTTPS support
```

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Manual testing completed
- [ ] Tests added/updated
- [ ] All tests passing

## Checklist
- [ ] Code follows project style
- [ ] Self-reviewed code
- [ ] Updated documentation
- [ ] Signed CLA
```

## 🏆 Recognition

Contributors will be:
- Listed in release notes
- Mentioned in the README (for significant contributions)
- Thanked in our hearts ❤️

## ❓ Questions?

- Open a discussion on GitHub
- Check existing issues and discussions
- Read the documentation thoroughly

## 📜 License Reminder

By contributing, you agree that your contributions will be dual-licensed under:
- AGPL-3.0 for the open source version
- Commercial license for paying customers

This dual licensing model helps ensure DNS Guardian remains sustainable while staying open source.

Thank you for helping make DNS Guardian better! 🚀