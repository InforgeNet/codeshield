<?php
/*
    codeshield - A simple but great solution against Denial of Service HTTP
    Copyright (C) 2014  Stefano Novelli

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Also add information on how to contact you by electronic and paper mail.

    If the program does terminal interaction, make it output a short
    notice like this when it starts in an interactive mode:

    codeshield  Copyright (C) 2014  Stefano Novelli
    This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

    The hypothetical commands `show w' and `show c' should show the appropriate
    parts of the General Public License.  Of course, your program's commands
    might be different; for a GUI interface, you would use an "about box".
    
    You should also get your employer (if you work as a programmer) or school,
    if any, to sign a "copyright disclaimer" for the program, if necessary.
    For more information on this, and how to apply and follow the GNU GPL, see
    <http://www.gnu.org/licenses/>.
    
    The GNU General Public License does not permit incorporating your program
    into proprietary programs.  If your program is a subroutine library, you
    may consider it more useful to permit linking proprietary applications with
    the library.  If this is what you want to do, use the GNU Lesser General
    Public License instead of this License.  But first, please read
    <http://www.gnu.org/philosophy/why-not-lgpl.html>.
    
    External Resources: Project HoneyPot (http://www.projecthoneypot.org/)

/!\ WARNING /!\
DON'T EDIT THIS FILE UNLESS YOU KNOW WHAT YOU'RE DOING
/!\ WARNING /!\
DON'T EDIT THIS FILE UNLESS YOU KNOW WHAT YOU'RE DOING
/!\ WARNING /!\
DON'T EDIT THIS FILE UNLESS YOU KNOW WHAT YOU'RE DOING
/!\ WARNING /!\
DON'T EDIT THIS FILE UNLESS YOU KNOW WHAT YOU'RE DOING

*/

//Include Config.php
require_once("config.php");


//Cookie Switcher
function make_goddamn_cookie()
{
    //Create Salt Cookie to prevent Cookied Proxies @ Fight the Lamah!
    global $saltcookie;
    $saltcookie = "antibot_".md5($salt.date(G).$honeypotapi.$_SERVER['REMOTE_ADDR'].$_SERVER['HTTP_USER_AGENT']);
    
}


make_goddamn_cookie();


if ($_COOKIE[$saltcookie]) {
    //Don't check the client, it's ok!
	ozh_httpbl_logme(false,	$_SERVER['REMOTE_ADDR']);
} else {
    //Start Check
    header_check($saltcookie);
	ozh_httpbl_check($saltcookie);
}

//This function controls if Server Load is > of max value
function header_check($saltcookie)
{
    $load = explode(" ",@file_get_contents('/proc/loadavg'));
    $loadint = intval($load[0]);

    if ($loadint >= $maxserverload)
	  
        {
            ozh_httpbl_logme($block,$ip,$type,$threat,$activity);
			ozh_httpbl_blockme($saltcookie);
			die();  
        }  
}

//Honeypot Project Function
function ozh_httpbl_check($saltcookie) {	
    
    if ($honeypot == 1 )
    {
    
	// your http:BL key 
	$apikey = $honeypotapi;
	
	// IP to test
	$ip = $_SERVER['REMOTE_ADDR'];
	
	// build the lookup DNS query
	// Example : for '127.9.1.2' you should query 'abcdefghijkl.2.1.9.127.dnsbl.httpbl.org'
	$lookup = $apikey . '.' . implode('.', array_reverse(explode ('.', $ip ))) . '.dnsbl.httpbl.org';
	
	// check query response
	$result = explode( '.', gethostbyname($lookup));
	
	if ($result[0] == 127) {
		// query successful !
		$activity = $result[1];
		$threat = $result[2];
		$type = $result[3];
		
		if ($type & 0) $typemeaning .= 'Search Engine, ';
		if ($type & 1) $typemeaning .= 'Suspicious, ';
		if ($type & 2) $typemeaning .= 'Harvester, ';
		if ($type & 4) $typemeaning .= 'Comment Spammer, ';
		$typemeaning = trim($typemeaning,', ');
		
		// Now determine some blocking policy
		if (
		($type >= 4 && $threat > 0) // Comment spammer with any threat level
			||
		($type < 4 && $threat > 20) // Other types, with threat level greater than 20
		) {
			$block = true;
		}
		
        //Final Honeypot Project Check
		if ($block) {
			ozh_httpbl_logme($block,$ip,$type,$threat,$activity);
			ozh_httpbl_blockme($saltcookie);
			die();
		}
        
        setcookie($saltcookie,true);
	}
    
    }
}


function ozh_httpbl_logme($block = false, $ip='', $type='',$threat='',$activity='') {
	$log = fopen('logs/block.log','a');
	$stamp = date('Y-m-d :: H-i-s');
	
	// Some stuff you could log for further analysis
	$page = $_SERVER['REQUEST_URI'];
	$ua = $_SERVER["HTTP_USER_AGENT"];
		
	if ($block) {
		fputs($log,"$stamp :: BLOCKED $ip :: $type :: $threat :: $activity :: $page :: $ua\n");
	/*} else {
		fputs($log,"$stamp :: UNBLCKD $ip :: $page :: $ua\n");
        I don't want else to log unblockeds'
        */
	}
	fclose($log);
}


function ozh_httpbl_blockme($saltcookie) {
	header('HTTP/1.0 503 Service Unavailable');

	echo "
    <script type='text/javascript'>
	function setcookie( name, value, expires, path, domain, secure ) {
		// set time, it's in milliseconds
		var today = new Date();
		today.setTime( today.getTime() );
	
		if ( expires ) {
			expires = expires * 1000 * 60 * 60 * 24;
		}
		var expires_date = new Date( today.getTime() + (expires) );
	
		document.cookie = name + \"=\" +escape( value ) +
		( ( expires ) ? \";expires=\" + expires_date.toGMTString() : \"\" ) + 
		( ( path ) ? \";path=\" + path : \"\" ) + 
		( ( domain ) ? \";domain=\" + domain : \"\" ) +
		( ( secure ) ? \";secure\" : \"\" );
	}	
	function letmein(cookie) {
		setcookie(cookie,'true',1,'/', '', '');
		location.reload(true);
	}
    letmein('$saltcookie');
	</script>

";

$lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
switch ($lang)
    {
        case "it":
            //echo "PAGE IT";
            require_once("lang/it.php");
            break;      
        default:
            //echo "PAGE EN - Setting Default";
            include("lang/en.php");//include EN in all other cases of different lang detection
            break;
    }
}

?>
