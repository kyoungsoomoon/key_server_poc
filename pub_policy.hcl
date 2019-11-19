path "secret/data/prod/publisher/pub_id_n" {
    capabilities = [ "create", "read", "update", "delete", "list"]
}

path "secret/metadata/prod/publisher/pub_id_n" {
    capabilities = [ "create", "read", "update", "delete", "list"]
}

path "auth/approle/role/pub_id_n" {
    capabilities = [ "create", "read", "update", "delete", "list"]
}

path "auth/token/revoke" {
    capabilities = [ "create", "read", "update", "delete", "list"]
}

path "auth/token/revoke-self" {
    capabilities = [ "create", "read", "update", "delete", "list"]
}