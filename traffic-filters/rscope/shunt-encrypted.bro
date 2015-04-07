export {

    redef SSL::disable_analyzer_after_detection = T;

}


event ssl_established(c: connection) &priority=-7 {

    mcore_apply_shunt_policy(c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, T);

}


event ssh_server_version(c: connection, version: string) &priority=-7 {

    mcore_apply_shunt_policy(c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, T);

}

