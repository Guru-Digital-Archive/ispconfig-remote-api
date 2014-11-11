<?php

require './vendor/autoload.php';

$cp       = new \GDM\ISPConfig\SoapClient('https://127.0.0.1:8080/remote/index.php', 'admin', 'mysecurepassword');
$clientId = $cp->clientAdd("My Client", "My Clients Company", "myclient", "myclientspassword", "contact@myclient.com", "000000");
$siteId   = false;
if ($clientId) {
    $siteId = $cp->sitesWebDomainAdd($clientId, "myclient.com", "255.255.255.1");
} else {
    echo "Failed to create client " . $cp->getLastException()->getMessage();
}

if ($siteId) {
    echo "Created client with id $clientId ";
    echo "Created site with id $siteId ";
} else {
    echo "Failed to create site " . $cp->getLastException()->getMessage();
}

