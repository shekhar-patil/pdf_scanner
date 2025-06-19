# PdfScanner

PdfScanner is a Ruby gem for scanning PDF files for potentially dangerous or unwanted features, such as JavaScript, embedded files, forms, and more. It uses configurable security policies to analyze PDF files and can quarantine files that violate your policies.

## Features

- Scans PDF files for scripts, attachments, forms, and other risky features
- Configurable security policies via YAML
- Supports encrypted PDFs (with password)
- Can quarantine files that violate policies
- Extensible and easy to integrate

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'pdf_scanner'
```

And then execute:

```sh
bundle install
```

Or install it yourself as:

```sh
gem install pdf_scanner
```

## Usage

### Basic Example

```ruby
require 'pdf_scanner'

scanner = PdfScanner::Scanner.new(
  target_file: '/path/to/file.pdf',
  config_file: '/path/to/pdfcop.conf.yml', # optional, uses default if omitted
  policy: 'standard',                      # optional, uses 'standard' if omitted
  dir: '/path/to/quarantine',              # optional, for quarantining
  passwd: 'password'                       # optional, for encrypted PDFs
)
result = scanner.scan

puts result.inspect
```

### Parameters

- `target_file` (required): Path to the PDF file to scan.
- `config_file` (optional): Path to the YAML config file with security policies.
- `policy` (optional): Policy name to use (default: `standard`).
- `dir` (optional): Directory to move/quarantine files that violate policies.
- `passwd` (optional): Password for encrypted PDFs.

### Return Value

The `scan` method returns a hash with two keys:
- `:rejected_policies` — Array of hashes with `:policy` and `:message` for each rejected policy.
- `:analysis_failure` — Array of hashes with `:error` and `:message` for analysis failures.

Example:

```ruby
{
  rejected_policies: [
    { policy: "standard", message: "[:allowJS]" }
  ],
  analysis_failure: []
}
```

## Configuration

Policies are defined in a YAML file (see `lib/pdf_scanner/config/pdfcop.conf.yml` for an example). Each policy is a set of boolean flags controlling which PDF features are allowed.

Example policy section:

```yaml
POLICY_STANDARD:
  allowParserErrors: false
  allowAttachments: false
  allowEncryption: false
  allowJS: false
  allowAcroForms: false
  # ... more options ...
```

## Command-Line Usage

You can also use the provided `bin/console` for interactive testing:

```sh
bin/console
```

## Development

After checking out the repo, run:

```sh
bin/setup
```

To install dependencies. You can also run:

```sh
bin/console
```

For an interactive prompt.

To install this gem onto your local machine:

```sh
bundle exec rake install
```

To release a new version, update the version number in `version.rb`, then run:

```sh
bundle exec rake release
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/shekhar-patil/pdf_scanner. Please adhere to the [code of conduct](CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](LICENSE.txt).
