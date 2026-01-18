# Contributing to CROSSRING

Thank you for your interest in contributing to CROSSRING!

## How to Contribute

### Bug Reports

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Windows version
   - Steps to reproduce
   - Expected vs actual behavior
   - Screenshots if applicable

### Feature Requests

1. Open a GitHub Discussion first
2. Describe the use case
3. Explain why it benefits the project

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Write/update tests
5. Ensure builds pass
6. Submit a Pull Request

## Development Setup

### Requirements
- Visual Studio 2022
- Windows SDK 10.0.22000+
- .NET 8 SDK

### Building
```powershell
git clone https://github.com/Shxlnh/crossring.git
cd crossring
# Open CROSSRING.sln in Visual Studio
# Build > Build Solution
```

### Testing
```powershell
# Run service in console mode for debugging
.\bin\Release\CrossringService.exe /console
```

## Code Style

### C++
- Use C++17 features
- Follow Microsoft C++ Core Guidelines
- Use smart pointers
- RAII for resource management

### C#
- Follow .NET naming conventions
- Use MVVM pattern
- Async/await for I/O operations

## Security

- Never store passwords
- Validate all inputs
- Use secure APIs
- Report vulnerabilities responsibly

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
