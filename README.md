This is a python script that connects to Tenable's SecurityCenter API and displays some targeted information.

It's titled ACAS because it was built around the need to target some DoD specific information, and ACAS is the DoD's name for
the Tenable suite. If you don't need some specifics like IAVMs, it's easy enough to strip out. 

The main purpose of this script was to provide a reporting feature that the native reports lacked, as well as display it in a 
classified environment on systems that did not have office or other software not native to the OS. 

The lacking feature was the ability to produce a small(ish) report that shows the plugin output for each vuln on each host.
This feature has been requested by the DoD community on software.forge.mil and it was approved, but never materialized due to 
lack of funding.

To avoid producing a document that needed Office or a PDF viewer, it spits HTML out to the console so you can view it in a browser.
You can redirect the output to an HTML file to save the results.

Future versions will add:
  - Output to CSV format for easy data manipulation
  - Dirty word list to auto-sanitize if you want to downgrade the file to an unclassified network
  - Collapsable groups in vulns with lots of grouped results
  - Classification banners

