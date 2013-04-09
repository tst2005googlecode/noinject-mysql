-- 
-- CONFIG GOES HERE
--
pt_fingerprint='/home/justin/plmce/pt-fingerprint'
db='percona'
table='whitelist'
exception_table = 'whitelist_exception'

-- If set to FALSE, only the first violation seen by this instance
-- of the proxy will be recorded (useful for collecting new patterns) 
-- I suggest leaving it set to true for normal usage
log_all_violations = true

-- The first query will retrieve all the whitelisted checksums
-- and cache them in memory.  This is more efficient than making
-- one round trip per query fingerprint, especially when the
-- number of unique fingerprints is large
preload_whitelist = true

-- NOINJECT blocking mode: [IMPORTANT]
-- --------------------------------------------------------------
-- PERMISSIVE MODE ('permissive'):
-- Allow suspect queries to execute but log their execution
--
-- RESTRICT MODE ('restrict'):
-- Block suspect queries and also log their execution
mode = 'permissive' 
-- mode = 'restrict' 

-- --------------------------------------------------------------
-- DO NOT MODIFY BELOW THIS POINT
-- --------------------------------------------------------------
fqtn =  db .. '.' .. table 
fqetn = db .. '.' .. exception_table 

-- a table which holds known fingerprints and if they are OK or not
-- always contains at least the three queries which are sent by the MySQL client
patterns = {}
patterns["5cba2034458b5bc9"] = 1 -- show databases
patterns["132628303f99240d"] = 1 -- show tables 
patterns["e3a3649c5fac418d"] = 1 -- select @@version_comment limit 1

orig_sql = "" -- This is the SQL which was sent by the client
fingerprint = "" -- this is the fingerprint of the orig_sql

client_ip = ""  -- this will hold the IP of the connecting client
client_username = "" -- this will hold the username of the connecting client

-- SQL to send instead, when an injection is detected
NOINJECT_SQL = "select 0 from dual limit 0";

-- Has the whitelist been preloaded?
if preload_whitelist == true then
	preloaded_whitelist = false
else
	-- pretend :)
	preloaded_whitelist = true
end
-- 
-- This is a proxy API interface call.  
-- The IP address of the remote client is captured here
--
function read_handshake() 
	client_ip = proxy.connection.client.src.name
end
--
-- This proxy API interface is used to capture the username
function read_auth()
	client_username = proxy.connection.client.username
end

-- capture the output from an exec call (exec captures the return code)
function my_exec(cmd)
	f = assert(io.popen(cmd, 'r'))
	s = assert(f:read('*a'))
	f:close()
	s=s:gsub("[\r\n]*", "")
	return s
end

-- invoke pt-fingerprint in a subshell and return the fingerprint checksum
function fingerprint_input(sql) 
	sql = sql:gsub("`", "``")
	sql = sql:gsub("\\", "\\\\")
	sql = sql:gsub('"', '\\"')
	cmd = pt_fingerprint .. ' --query "' .. sql .. '"'
	return my_exec(cmd)
end

--
-- This function injects a SQL statement into the stream to log a 
-- violation into the exception log
--
function log_violation() 
	new_sql = orig_sql:gsub("'", "''")
	-- the insert has an IGNORE clause to allow a unique key on the checksum field
	-- this will allow the tool to collect only one example of each query fingerprint
	-- in the exception table.  This is very useful for collecting the initial set
	-- of fingerprints for an application
	insert_sql = "insert IGNORE into " .. fqetn .. " ( checksum, query_text, exception_when, exception_ip, exception_user, action ) VALUES ("
	insert_sql = insert_sql .. "CONV('" .. fingerprint .. "', 16, 10), '" .. new_sql .. "', now(),'" .. client_ip .. "', '" .. client_username .. "', '" 
	if mode == 'permissive' then
		insert_sql = insert_sql .. "allowed')"
	else
		insert_sql = insert_sql .. "denied')"
	end

	proxy.queries:append(15, packet_header .. insert_sql, {resultset_is_needed = true})
end

--
-- This function injects a SQL statement into the stream to log a 
-- violation into the exception log
--
function insert_into_whitelist() 
	local new_sql = orig_sql:gsub("'", "''")
	local insert_sql = "insert into " .. fqtn .. " ( checksum, fingerprint, sample, first_seen, last_seen, comments ) VALUES (CONV('" .. fingerprint .. "', 16, 10),'" .. fingerprint .. "','" .. new_sql .. "', now(),now(),'discovered by noinject proxy from client:" .. client_ip .. ", user: " .. client_username .. "') on duplicate key update last_seen=now()"

	proxy.queries:append(16, packet_header .. insert_sql, {resultset_is_needed = true})
end


packet_header = ""

--
-- This proxy API is called when a query is sent to the server
--
function read_query(packet)
	packet_header = packet:sub(1,1)
	read_query_error=false

	if(preloaded_whitelist == false and preload_whitelist == true) then
		preloaded_whitelist = true
		proxy.queries:append(5, packet_header .. "SELECT conv(checksum, 10, 16) checksum from " .. fqtn .. " where reviewed_by = 'allowed'", { resultset_is_needed = true } )
	end 


	if packet:byte() == proxy.COM_QUERY then
		orig_sql = packet:sub(2)
	end

	-- TODO: speed this up, it is 4ms to spin up the interpreter and 1ms to 
	-- do the actual fingerprinting
	fingerprint=fingerprint_input(orig_sql) 

	if patterns[fingerprint] == nil then
		-- lookup the query
		lookup_sql = "SELECT 1 from " .. fqtn .. " WHERE checksum = CONV('" .. fingerprint .. "', 16, 10) and reviewed_by = 'allowed'"
		proxy.queries:append(10,packet_header .. lookup_sql, {resultset_is_needed = true})
	elseif patterns[fingerprint] == 1 then
		-- send the original SQL to the server
		proxy.queries:append(20,packet_header .. orig_sql, {resultset_is_needed = true})
	elseif patterns[fingerprint] == 2 then
		-- send the original SQL to the server, but log a violation to the exception table first
		if log_all_violations == true then log_violation() end
		proxy.queries:append(20,packet_header .. orig_sql, {resultset_is_needed = true})
	else
		-- send an empty resultset to the server (via the user supplied SQL above)
		if log_all_violations == true then log_violation() end
		log_violation()
		proxy.queries:append(20,packet_header .. NOINJECT_SQL, {resultset_is_needed = true})
	end

	return proxy.PROXY_SEND_QUERY
	
end

--
-- This proxy API function is called when a query result is returned
-- from injected queries which have been marked as {resultset_is_needed = true}
--
function read_query_result(inj)
	-- This is the result from the INSERT into the exception log or whitelist table
	if inj.id == 15 or inj.id == 16 then
		return proxy.PROXY_IGNORE_RESULT
	-- Preload the list of whitelisted queries
	elseif inj.id == 5 then
		for row in inj.resultset.rows do
			patterns[row[1]] = 1
		end
		return proxy.PROXY_IGNORE_RESULT
	-- This is the result of a whitelist lookup
	elseif inj.id == 10 then
		found_rows = 0
    		for row in inj.resultset.rows do
      			found_rows = 1
    		end

		-- if a row was not returned by the query then the original query
		-- was not whitelisted
		if found_rows == 0 then
			insert_into_whitelist()
			log_violation()
			if mode == 'permissive' then
				-- don't keep checking but log the accesses
				patterns[fingerprint] = 2
			else
				-- block the access, return empty set to client (the result from the whitelist lookup) 
				patterns[fingerprint] = 3 
				proxy.queries:append(20, packet_header .. NOINJECT_SQL, {resultset_is_needed = true})
                		return proxy.PROXY_SEND_QUERY
			end
		end

		-- run the original query because it is whitelisted or 
		-- because the proxy is running in permissive mode
		patterns[fingerprint] = 1;  -- prevent the extra roundtrip in the future

		-- send the original query
		proxy.queries:append(20, packet_header .. orig_sql)
		return proxy.PROXY_SEND_QUERY
	end

end

