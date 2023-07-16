pdnslog("pdns-recursor Lua script starting!", pdns.loglevels.Warning)


function fileExists(file)
  local f = io.open(file, "rb")
  if f then
    f:close()
  end
  return f ~= nil
end

function loadFile(filename, list)
  if fileExists(filename) then
    for line in io.lines(filename) do
      list:add(line)
    end
    pdnslog("Lua script: " .. filename .. " successfully loaded", pdns.loglevels.Notice)
  else
    pdnslog("Lua script: could not open file " .. filename, pdns.loglevels.Warning)
  end
end


function preresolve(dq)
  if blockset:check(dq.qname) then
   pdnslog("Dropping query for "..dq.qname:toString().." from "..dq.remoteaddr:toString(), pdns.loglevels.Notice)
   dq.appliedPolicy.policyKind = pdns.policykinds.Drop
   blocklist_metric:inc()
   return false -- recursor still needs to handle the policy
  end

  return false
end

blockset = newDS()
loadFile("/etc/powerdns/blocklist", blockset)
blocklist_metric = getMetric("blocklist_hits")