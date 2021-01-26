/**
 * Fubuki Network Toolbox - he-route-filter-detect.js
 * Copyright (c) edisonlee55
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

"use strict";

const asnRegEx = /^[0-9]+$/;

let getRoute = (asn, ipVer) => {
    if (!(asn && ipVer)) {
        throw new Error("Argument missing");
    }
    asn = asn.toString();
    ipVer = ipVer.toString();
    if (!(asn.match(asnRegEx))) {
        throw new Error("Invalid ASN");
    }
    if (!(ipVer === "4" || ipVer === "6")) {
        throw new Error("Invalid IP Version");
    }
    return fetch(
        `http://routing.he.net/index.php?cmd=display_filter&as=${asn}&af=${ipVer}&which=reasons`
    )
        .then((response) => {
            return response.text();
        })
        .then(function (html) {
            let parser = new DOMParser();
            let document = parser.parseFromString(html, "text/html");
            let routeList = document.getElementsByTagName("pre");
            if (!(routeList && routeList.length > 0)) {
                return null;
            }
            routeList = routeList[0].textContent.split("\n");
            let route = [];
            if (routeList && Array.isArray(routeList) && routeList.length > 0) {
                routeList.forEach((e) => {
                    if (e) route.push(e.split(","));
                });
            }
            return route;
        })
        .catch(function (err) {
            console.error("Cannot get route from HE:", err);
        });
};

// rpkiStatus = {"VALID", "UNKNOWN", "INVALID_ASN", "INVALID_LENGTH"};
let matchRawRPKI = async (asn, ipVer, rpkiStatus) => {
    if (!(asn && ipVer && rpkiStatus)) {
        throw new Error("Argument missing");
    }
    asn = asn.toString();
    ipVer = ipVer.toString();
    if (!(asn.match(asnRegEx))) {
        throw new Error("Invalid ASN");
    }
    if (!(ipVer === "4" || ipVer === "6")) {
        throw new Error("Invalid IP Version");
    }
    let route = await getRoute(asn, ipVer);
    let rpkiRegEx = new RegExp(
        String.raw`.*origin (.*) RPKI status (${rpkiStatus}).*`
    );
    if (!(route && Array.isArray(route) && route.length > 0)) {
        return null;
    }
    let matchedStrList = [];
    route.forEach(e => {
        if (e[2].match(rpkiRegEx)) {
            matchedStrList.push(e);
        }
    });
    return matchedStrList;
};

// TODO: requestType = {"asn", "ip_asn", "ip", "ip_filter_status", "filter_status_only", "description_text"}
// keepDuplicate: optional (default = true)
let matchRPKI = async (asn, ipVer, rpkiStatus, requestType, keepDuplicate) => {
    if (!(asn && ipVer && rpkiStatus && requestType)) {
        throw new Error("Argument missing");
    }
    asn = asn.toString();
    ipVer = ipVer.toString();
    if (!(asn.match(asnRegEx))) {
        throw new Error("Invalid ASN");
    }
    if (!(ipVer === "4" || ipVer === "6")) {
        throw new Error("Invalid IP Version");
    }
    if (keepDuplicate === undefined) {
        keepDuplicate = true; // keepDuplicate Default: true
    }
    else if (typeof keepDuplicate !== "boolean") {
        throw new Error("Invalid Keep Duplicate Boolean");
    }
    let rpkiRegEx = new RegExp(
        String.raw`.*origin (.*) RPKI status (${rpkiStatus}).*`
    );
    let matchedRPKI = await matchRawRPKI(asn, ipVer, rpkiStatus);
    if (!(matchedRPKI && Array.isArray(matchedRPKI) && matchedRPKI.length > 0)) {
        return null;
    }
    let rpkiRes = [];
    switch (requestType) {
        case "asn":
            matchedRPKI.forEach(e => {
                if (e[2].match(rpkiRegEx)) {
                    rpkiRes.push(e[2].match(rpkiRegEx)[1]);
                }
            });
            if (!keepDuplicate) {
                rpkiRes = [...new Set(rpkiRes)];
            }
            return rpkiRes;
        case "ip":
            matchedRPKI.forEach(e => {
                rpkiRes.push(e[0]);
            });
            if (!keepDuplicate) {
                rpkiRes = [...new Set(rpkiRes)];
            }
            return rpkiRes;
        case "ip_filter_status":
            matchedRPKI.forEach(e => {
                e.pop();
                rpkiRes.push(e);
            });
            if (!keepDuplicate) {
                rpkiRes = [...new Set(rpkiRes)];
            }
            return rpkiRes;
        case "filter_status_only":
            matchedRPKI.forEach(e => {
                rpkiRes.push(e[1]);
            });
            if (!keepDuplicate) {
                rpkiRes = [...new Set(rpkiRes)];
            }
            return rpkiRes;
        case "description_text":
            matchedRPKI.forEach(e => {
                rpkiRes.push(e[2]);
            });
            if (!keepDuplicate) {
                rpkiRes = [...new Set(rpkiRes)];
            }
            return rpkiRes;
        default:
            throw new Error("Invalid Request Type");
    }
}
