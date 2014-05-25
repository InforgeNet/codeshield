<?php
/*
    codeshield - A simple but great solution against Denial of Service HTTP
    Copyright (C) 2014  Inforge.net

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
 
class codeshield{
 
    private $salt = '<your salt>'; // Salt encryption. WARNING: Use special characters and change default value
    public $honeypot = false; // 1 / true = Use honeypot - 0 / false = Don't use honeypot
    public $honeypotapi = ''; // http://www.projecthoneypot.org/httpbl_configure.php
    public $maxserverload = 6; // 0 = all filter connections - > 0 = max server load
    public $threatmax = 20; // http://www.projecthoneypot.org/threat_info.php
    public $typehold = 2; // Up to that type allow
 
    /* WARNING: DON'T TOUCH */
    private $ip = ''; // ip client
    private $cookie_name = ''; // cookie name
    private $searchenginemap = array( // Search engine map
        0   => 'Uncodumented',
        1   => 'AltaVista',
        2   => 'Ask',
        3   => 'Baidu',
        4   => 'Excite',
        5   => 'Google',
        6   => 'Looksmart',
        7   => 'Lycos',
        8   => 'MSN',
        9   => 'Yahoo',
        10  => 'Cuil',
        11  => 'InfoSeek',
        12  => 'Miscellaneous');
 
    /***************/
    public function __construct(){
 
        $this->ip = $_SERVER['REMOTE_ADDR'];
        $this->cookie_name = 'antibot_'.md5($salt.date('G').$this->honeypotapi.$this->ip); // Ex: antibot_a60c3cf32b4c5adc4da680fc25d85113
 
        if(!isset($_COOKIE[$this->cookie_name])){
 
            setcookie($this->cookie_name, true);
 
            $this->check_server_load();
 
            if($this->honeypot) // honeypot is enabled?
                $this->check_honeypot();
 
        }
 
    }
 
    private function get_server_load(){
 
        $load = 0;
        $php_os = strtolower(PHP_OS);
 
      if(strpos($php_os, 'win') === false) $load = sys_getloadavg()[0]; /* linux */ else{
 
            $wmi = new COM("Winmgmts://");
            $query = $wmi->execquery("SELECT LoadPercentage FROM Win32_Processor");
 
            $cpu_num = 0;
            $load_total = 0;
 
            foreach($query as $cpu){
 
                $cpu_num++;
                $load_total += $cpu->loadpercentage;
 
            }
 
            $load = $load_total / $cpu_num;
 
        }
 
        return intval($load);
 
    }
 
    private function check_server_load(){
 
        $load_server = $this->get_server_load();
 
        if($load_server >= $this->maxserverload){
 
            $this->log('Server overload', $load_server, 'null');
            $this->stamp();
 
        }
 
    }
 
    private function check_honeypot(){
 
        $reverse_ip = implode('.', array_reverse(explode('.', $this->ip)));
        $httpbl = $this->honeypotapi.'.'.$reverse_ip.'.dnsbl.httpbl.org';
        $gethostbyname = gethostbyname($httpbl);
        $result = explode('.', $gethostbyname);
 
        if(!empty($result) && $gethostbyname != $httpbl && $result[0] == 127){
 
            $activity = $result[1];
            $threat = $result[2];
            $cthreat = $result[2];
            $type = $result[3];
            $typemeaning = array('No Malicious');
 
            if($type & 0){
 
                $threat = 0;
                $activity = 'null';
                $searchenginename = array_key_exists($cthreat, $this->searchenginemap) ? $this->searchenginemap[$cthreat] : 'Unknown';
                $typemeaning[] = 'Search Engine - '.$searchenginename;
 
            }else{
 
                if($type & 1) $typemeaning[] = 'Suspicious';
                if($type & 2) $typemeaning[] = 'Harvester';
                if($type & 3) $typemeaning[] = 'Comment Spammer';
 
            }
 
            $typemeaning = trim(implode(', ', $typemeaning), ', ');
 
            if($threat >= $this->threatmax && $type >= $this->typehold){
 
                $this->log($typemeaning, $threat, $activity);
                $this->stamp();
 
            }
 
        }
 
    }
 
    private function stamp(){
 
        header('HTTP/1.0 503 Service Unavailable');
 
        /* redirection between 2 seconds */
        echo "<script type='text/javascript'>setTimeout(function(){window.location = window.location.href}, 2000);</script>Check if you are a bot...";
 
        exit;
 
    }
 
    private function log($type = '?', $threat = '?', $activity = '?'){
 
        $now = date('d-m-Y H-i-s');
        $status = "BLOCKED"; // for future implementation
        $request_uri = $_SERVER['REQUEST_URI'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'];
 
        file_put_contents('block.log', $now." :: ".$status." ".$this->ip." :: ".$type." :: ".$threat." :: ".$activity." :: ".$request_uri." :: ".$user_agent."\n", FILE_APPEND);
 
    }
 
}
 

 
############################################# Include file in the config file or in all files
include "config.php";
 
############################################# Call this in index or in all files
$codeshield = new codeshield();
 
?>