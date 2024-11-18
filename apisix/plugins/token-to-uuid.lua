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
    core.log.info("Exclude Rewrite URIs: ", core.json.encode(conf.exclude_rewrite_uris))
    local request_uri = ngx.var.uri

    -- Check if the current URI is in the exclusion list
    if conf.exclude_rewrite_uris and type(conf.exclude_rewrite_uris) == "table" then
        for _, uri in ipairs(conf.exclude_rewrite_uris) do
            -- Convert the excluded URI template to Lua pattern, supporting dynamic path parameters
            local escaped_uri = uri:gsub("([%.%+%-%*%?%[%]%^%$%(%)])", "%%%1")
            local pattern = "^" .. escaped_uri:gsub("{[%w_]+}", "[^/]+") .. "$"
            core.log.info("request_uri: ", request_uri, "pattern: ", pattern, "uri: ", uri)
            if request_uri:match(pattern) then
                core.log.warn("URI ", request_uri, " matches exclusion pattern ", uri, ", skipping rewrite")
                return
            end
        end
    end
    
    -- Step 1: Get the Authorization token from the request header
    local headers = ngx.req.get_headers()
    local token = headers["Authorization"]
    local request_id = headers["Request-Id"]

    if not request_id then
        core.log.warn("Request-Id not found, generating a new one")
        request_id = uuid()
    end

    if not token or token == "" then
        core.log.warn("Authorization token not found")
        return _M.unauthorized(request_id)
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
            ["Request-Id"] = request_id
        },
        ssl_verify = false
    })

    if not res then
        core.log.error("Failed to request USER service: ", err)
        return _M.unauthorized(request_id)
    end

    if res.status ~= 200 then
        core.log.error("Failed to get UID, status code: ", res.status)
        return _M.unauthorized(request_id)
    end

    local cjson = require("cjson")
    -- Check if response body is empty or "null"
    if not res.body or res.body == "" or res.body == "null" then
        core.log.error("Empty or null response body")
        return _M.unauthorized(request_id)
    end

    local res_body, err = cjson.decode(res.body)
    if not res_body then
        core.log.error("Failed to decode response body: ", err)
        return _M.unauthorized(request_id)
    end

    -- Check if res_body is nil or not a table
    if type(res_body) ~= "table" then
        core.log.error("Invalid response body format")
        return _M.unauthorized(request_id)
    end

    local user_id = res_body.user_id
    if not user_id then
        core.log.error("user_id is empty")
        return _M.unauthorized(request_id)
    end

    -- Step 3: Rewrite the user_id into the request header
    ngx.req.set_header("UID", user_id)

    core.log.info("Rewritten user_id into request header: ", user_id)
end

-- Unified Unauthorized response function
function _M.unauthorized(request_id)
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["Content-Type"] = "application/json"
    ngx.header["Request-Id"] = request_id
    ngx.say('{"error": "Unauthorized"}')
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

return _M
