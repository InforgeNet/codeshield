Project name: codeshield
Version: 0.1
Provider: Inforge.net
Author: Stefano Novelli (murdercode)
Description: A simple but great solution against Denial of Service HTTP
Programming Language: PHP5, Javascript
External Resources: Project HoneyPot (http://www.projecthoneypot.org/)


Tired of DDoS HTTP attacks on your server? Check out this script!
============

codeshield is a simple but effective tool to balance the load of any webserver. Being built in PHP it does not need to be configured with Apache, Nginx etc ... but is included directly on each page of a website and perform each operation automatically and without the intervention of the visitor.

@@ How to install @@
First of all, you must download the script and extract the contents to a folder of your choice, and then copy all the contents inside FTP to your website.
Let's assume that your script is inside www.yourwebsite.net/codeshield/

@@ Configure your script @@
At this point you need to edit the config.php file that resides within /codeshield/config.php.
To do this we must change the FTP (preferably with an editor) and NOT by navigating the browser.
Within this script will find ... ####### ATWORK ##########

@@ Include your script (for Custom Website Only!) @@
We assume that your website has LEAST a script called for every page. Usually, this file allows you to create connections to the database, configuration files, etc., or a file that creates the output of your script.
To function properly, the script must be called BEFORE any print output, so before any printed text in any language.
-> Here the include <-

@@ Include your script (for vBulletin 4 Only!) @@
####### ATWORK ##########

** Credits **
Nobody wants to help me? <3
