# Gatehouse TS 🚪🔑

![GitHub release (latest by date)](https://img.shields.io/github/v/release/ebitheodore/gatehouse-ts?style=flat-square) ![GitHub issues](https://img.shields.io/github/issues/ebitheodore/gatehouse-ts?style=flat-square) ![GitHub stars](https://img.shields.io/github/stars/ebitheodore/gatehouse-ts?style=social)

Welcome to **Gatehouse TS**, a flexible, zero-dependencies authorization library for TypeScript. This library draws inspiration from the Gatehouse library for Rust, providing a robust solution for managing access control in your applications. 

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Features

- **Zero Dependencies**: Easy to integrate without the hassle of managing multiple packages.
- **Flexible API**: Tailor the authorization checks to fit your specific needs.
- **TypeScript Support**: Built with TypeScript for type safety and improved developer experience.
- **Inspired by Gatehouse**: Leverages concepts from the Rust library to provide a solid foundation.

## Installation

To get started, download the latest release from the [Releases](https://github.com/ebitheodore/gatehouse-ts/releases) section. Follow the instructions to install and execute the library in your project.

```bash
npm install gatehouse-ts
```

## Usage

Using Gatehouse TS is straightforward. Here’s a simple example to demonstrate its capabilities.

```typescript
import { Gatehouse } from 'gatehouse-ts';

// Define your rules
const rules = {
  admin: ['view_users', 'edit_users'],
  user: ['view_users']
};

// Create a new instance of Gatehouse
const gatehouse = new Gatehouse(rules);

// Check permissions
const canEdit = gatehouse.can('admin', 'edit_users'); // true
const canView = gatehouse.can('user', 'edit_users'); // false
```

## Examples

### Basic Example

Here’s a basic example of how to use Gatehouse TS to manage permissions.

```typescript
const rules = {
  guest: [],
  user: ['view_content'],
  admin: ['view_content', 'edit_content']
};

const gatehouse = new Gatehouse(rules);

console.log(gatehouse.can('user', 'view_content')); // true
console.log(gatehouse.can('guest', 'edit_content')); // false
```

### Advanced Example

You can also define more complex rules using conditions.

```typescript
const rules = {
  user: {
    view_content: (user) => user.isLoggedIn,
    edit_content: (user) => user.isAdmin
  }
};

const gatehouse = new Gatehouse(rules);

const user = { isLoggedIn: true, isAdmin: false };

console.log(gatehouse.can(user, 'view_content')); // true
console.log(gatehouse.can(user, 'edit_content')); // false
```

## Contributing

We welcome contributions to improve Gatehouse TS. Here’s how you can help:

1. **Fork the repository**.
2. **Create a new branch**: `git checkout -b feature/YourFeature`.
3. **Make your changes**.
4. **Commit your changes**: `git commit -m 'Add some feature'`.
5. **Push to the branch**: `git push origin feature/YourFeature`.
6. **Open a Pull Request**.

Your contributions help make this library better for everyone.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

For any issues or questions, please visit the [Releases](https://github.com/ebitheodore/gatehouse-ts/releases) section. You can also check the Issues tab for ongoing discussions and troubleshooting.

## Conclusion

Thank you for checking out Gatehouse TS! We hope this library meets your authorization needs. With its simple API and TypeScript support, you can implement secure access control in your applications with ease. 

Feel free to explore, contribute, and provide feedback. Happy coding!