--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local ngx = ngx
local core = require("apisix.core")
local plugin = require("apisix.plugin")
local upstream = require("apisix.upstream")

local schema = {
    type = "object",
    properties = {
        user_service_url = {type = "string", minLength = 1, pattern = "^(http|https)://"},
        get_uid_endpoint = {type = "string", minLength = 1, pattern = "^/?.+"},
        exclude_rewrite_uris = {
            type = "array",
            items = {type = "string", pattern = "^/?.+"},
            description = "List of URIs that do not need to execute the rewrite function"
        },
    },
    required = {"user_service_url", "get_uid_endpoint"},
}

local plugin_name = "token-to-uuid"

local _M = {
    version = 0.1,
    priority = 99,
    name = plugin_name,
    schema = schema
}

-- Check configuration schema
function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(metadata_schema, conf)
    end
    return core.schema.check(schema, conf)
end

-- Plugin initialization
function _M.init()
    -- Called when the plugin is loaded
    local attr = plugin.plugin_attr(plugin_name)
    if attr then
        core.log.info(plugin_name, " got plugin attribute value: ", attr.val)
    end
end

-- Plugin destruction
function _M.destroy()
    -- Called when the plugin is unloaded
end

-- Optimized rewrite function
function _M.rewrite(conf, ctx)
    local request_uri = ngx.var.uri

    -- Check if the current URI is in the exclusion list
    if conf.exclude_rewrite_uris and type(conf.exclude_rewrite_uris) == "table" then
        for _, uri in ipairs(conf.exclude_rewrite_uris) do
            if uri == request_uri then
                core.log.info("URI ", request_uri, " is in the exclusion list, skipping rewrite")
                return
            end
        end
    end
    
    -- Step 1: Get the Authorization token from the request header
    local headers = ngx.req.get_headers()
    local token = headers["Authorization"]

    if not token or token == "" then
        core.log.warn("Authorization token not found")
        return _M.unauthorized()
    end

    -- Step 2: Call the getUID interface of the USER service, and put the Authorization token in the request header
    local http = require("resty.http")
    local httpc = http.new()

    -- Use the USER service URL and getUID interface name from the configuration
    local user_service_url = string.format("%s%s", conf.user_service_url, conf.get_uid_endpoint)

    local res, err = httpc:request_uri(user_service_url, {
        method = "GET",
        headers = {
            ["Authorization"] = token,
        },
        ssl_verify = false
    })

    if not res then
        core.log.error("Failed to request USER service: ", err)
        return _M.unauthorized()
    end

    if res.status ~= 200 then
        core.log.error("Failed to get UID, status code: ", res.status)
        return _M.unauthorized()
    end

    -- Parse the response body, assuming it returns a JSON structure containing uuid
    local cjson = require("cjson")
    local res_body = cjson.decode(res.body)
    local uuid = res_body.uuid
    if not uuid or uuid == "" then
        core.log.error("uuid is empty")
        return _M.unauthorized()
    end

    -- Step 3: Rewrite the uuid into the request header
    ngx.req.set_header("UID", uuid)

    core.log.info("Rewritten uuid into request header: ", uuid)
end

-- Unified Unauthorized response function
function _M.unauthorized()
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error": "Unauthorized"}')
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

return _M