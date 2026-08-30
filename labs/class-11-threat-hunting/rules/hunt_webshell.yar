rule Class11_Generic_PHP_Webshell
{
    meta:
        author      = "SOC Command - Class 11"
        description = "Hunts common PHP webshell primitives in web roots"
        reference   = "Threat Hunting Strategy, IOC Management & Threat Intel Integration"
        severity    = "high"

    strings:
        $a = "eval(base64_decode(" nocase
        $b = "passthru("           nocase
        $c = "shell_exec("         nocase
        $d = "system($_GET["       nocase
        $e = "assert($_POST["      nocase
        $f = "$_REQUEST['cmd']"    nocase

    condition:
        any of them
}
