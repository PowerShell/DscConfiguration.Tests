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
* Fixed so the correct path is used for property WindowsOSVersion in the module
  manifest (issue #24).
* Pester test result file is only uploaded if the test are running in AppVeyor
  (issue #26).
* The Pester test result file is removed after the file has been uploaded
  (issue #26).
* Fixed so that latest Pester version can be installed on a Windows 10 or
  Windows Server 2016 where Pester module is signed (issue #29).
* Fixed so that more than one required module can be loaded (issue #32).
