# DSCConfiguration.Tests

This repository provides test automation scripting that are intended to
accelerate iterative authoring of DSC Configurations by hosting tests
on Azure.

## Versions

### Unreleased

* README.MD:
  * Fixed markdown rule violations.
  * Added Change Log.
* Added support for specifying the Azure Data center location to use
  by defining the `$ENV:Location` environment variable. Will default
  to 'EastUS2' if not specified.
* NUnit Pester Test results uploaded to AppVeyor as artifacts.
* Updated `New-ResourceGroupandAutomationAccount` to automatically
  register `Microsoft.Automation` resource provider.
