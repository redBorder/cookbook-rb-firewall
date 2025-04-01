# cookbook-rb-firewall

[![Build Status][build-shield]][build-url]
[![Linters][linters-shield]][linters-url]
[![License][license-shield]][license-url]

<!-- Badges -->
[build-shield]: https://github.com/redBorder/cookbook-rb-firewall/actions/workflows/rpm.yml/badge.svg?branch=master
[build-url]: https://github.com/redBorder/cookbook-rb-firewall/actions/workflows/rpm.yml?query=branch%3Amaster
[linters-shield]: https://github.com/redBorder/cookbook-rb-firewall/actions/workflows/lint.yml/badge.svg?event=push
[linters-url]: https://github.com/redBorder/cookbook-rb-firewall/actions/workflows/lint.yml
[license-shield]: https://img.shields.io/badge/license-AGPLv3-blue.svg
[license-url]: https://github.com/cookbook-rb-firewall/blob/HEAD/LICENSE

Cookbook to install and configure redborder firewall

### Platforms

- Rocky Linux 9

### Chef

- Chef 15.1 or later

## Building

- Build rpm package for redborder platform:
  * git clone https://github.com/redborder/cookbook-rb-firewall.git
  * cd cookbook-rb-firewall
  * make
  * RPM packages is under packaging/rpm/pkgs/

## Contributing

1. Fork the repository on Github
2. Create a named feature branch (like `add_component_x`)
3. Write your change
4. Write tests for your change (if applicable)
5. Run the tests, ensuring they all pass
6. Submit a Pull Request using Github

## License and Authors

GNU AFFERO GENERAL PUBLIC LICENSE Version 3, 19 November 2007
Authors: Nils Verschaeve <nverschaeve@redborder.com>
