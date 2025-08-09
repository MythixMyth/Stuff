type AcceptedValue = RBXScriptConnection | Instance
export type Cleaner = {[any] : AcceptedValue} & () -> ()

--[[
	Simpler version of maid 
	specifically for RBXScriptConnections quick disconnecting

Example Usage:

local Clean = require(...)
local Object = Clean(function() print("Successfuly cleaned up everything") end)

-- Object["Yo"] registers as a connection
Object["Yo"] = game:GetService("RunService").Heartbeat:Connect(function(dt) end)

-- Cleanup
Object()
]]
local TypesHash = {
  ["RBXScriptConnection"] = function(v) v:Disconnect() end,
  ["Instance"] = function(v) v:Destroy() end,
  ["thread"] = function(v) task.cancel(v) end
}

return function( CleanupCallback : (...any)->(...any)? ) : Cleaner
	local self = setmetatable({},{
		__call = function(selfv,...)
			for k,v in pairs(selfv) do
				TypesHash[typeof(v)](v)
				rawset(selfv,k, nil)
			end
			if CleanupCallback then CleanupCallback(...) end
		end,
      __newindex = function(self,key,value)
        if not TypesHash[typeof(value)] then error("Invalid datatype insertion to Cleaner: ".. debug.traceback("",2),2) end
        return rawset(self,key,value)
      end
	})
	return self
end
