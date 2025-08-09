-- Antiexploit client tool written by @my7hix
--[[
	Description:
		A function that returns an immutable metatable with locked index and perhaps newindex to prevent visibility
		to getupvalues and other exploit methods like getgc; The table is shown as empty userdata and when used to portray
		metatable through tostring or __metatable it is shown as nil. This is to defer exploiters from reading or writing
		data used in upvalues. ( Proven works best against npcs )
		
	Optimizations:
		- Minimal deep copying (only when necessary)
		- Cached method functions
		- Reduced metamethod overhead
		- Fast type checking
		- Optimized for integers and simple data types
	When To Use:
		When you have essential upvalues or constants that you want to hide from exploiters, this is the way to go.
]]

-- Fast type checking lookup hashtable
local ALLOWED_TYPES = {
	["nil"] = true,
	["boolean"] = true, 
	["number"] = true,
	["string"] = true,
	["function"] = true,
	["userdata"] = true,
	["thread"] = true,
	["table"] = true
}

local function smartCopy(value, visited)
	visited = visited or {}

	local t = type(value)
	if t ~= "table" then
		return value -- No copying needed for primitives
	end

	-- Check for circular reference
	if visited[value] then
		return visited[value] -- Return already copied table
	end

	local hasMetatable = getmetatable(value) ~= nil
	local copy = {}

	-- Register the copy early to handle self-references
	visited[value] = copy

	-- Copy table contents
	for k, v in pairs(value) do
		copy[k] = type(v) == "table" and smartCopy(v, visited) or v
	end

	-- Handle metatable if present
	if hasMetatable then
		setmetatable(copy, smartCopy(getmetatable(value), visited))
	end

	return copy
end

-- Pre-allocated error functions to avoid creating new ones
local function readonly_error() error("", 2) end
local function tostring_error() error("", 2) end

return function(Data, AllowWrite)
	-- Fast type validation
	if not ALLOWED_TYPES[type(Data)] then
		error("Uncompatible data type.", 2)
	end

	-- Create protected copy only when necessary
	local protectedData = type(Data) == "table" and smartCopy(Data) or Data
	local isTable = type(protectedData) == "table"

	-- Pre-create method functions to avoid recreation
	local get_method = function(_, key)
		if isTable then
			if key == nil then
				return smartCopy(protectedData)
			else
				local value = rawget(protectedData, key)
				return type(value) == "table" and smartCopy(value) or value
			end
		else
			return protectedData
		end
	end

	local set_method = AllowWrite and function(_, key, newValue)
		if not ALLOWED_TYPES[type(newValue)] then
			error("", 2)
		end

		if isTable and key ~= nil then
			rawset(protectedData, key, type(newValue) == "table" and smartCopy(newValue) or newValue)
		else
			protectedData = type(newValue) == "table" and smartCopy(newValue) or newValue
			isTable = type(protectedData) == "table"
		end
	end or nil

	local index_method = function(_, k)
		if k == "_get" or k == "Get" then
			return get_method
		elseif (k == "_set" or k == "Set") and AllowWrite then
			return set_method
		end
		error("", 2)
	end

	local metatable = {
		__index = index_method,
		__newindex = readonly_error,
		__metatable = nil,
		__tostring = tostring_error,
		__call = function(self)
			protectedData = nil
			setmetatable(self, nil)
			-- Clear the proxy
			for i = 1, #self do
				self[i] = nil
			end
		end
	}

	return setmetatable({}, metatable)
end
