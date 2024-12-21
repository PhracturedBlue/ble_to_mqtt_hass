local Class = {}
Class.__index = Class


function Class:inherit()
  local Subclass = {}
  Subclass.__index = Subclass
  -- Note how `self` in this case is the parent class, as we call the method like `SomeClass:inherit()`.
  setmetatable(Subclass, self)
  return Subclass
end

-- By default, let's make the base `Class` impossible to instantiate.
-- This should catch bugs if a subclass forgets to override `initialize`.
function Class.initialize()
  error("this class cannot be initialized")
end

-- `...` is Lua's notation for collecting a variable number of arguments
function Class:new(...)
  local instance = {}
  -- `self` is the class we're instantiating, as this method is called like `MyClass:new()`
  setmetatable(instance, self)
  -- We pass the instance to the class's `initialize()` method, along with all the arguments
  -- we received in `new()`.
  self.initialize(instance, ...)
  return instance
end

return Class
