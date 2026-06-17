description = "Marca servicios potencialmente inseguros para LuaNetSentinel"
categories  = {"safe", "discovery"}
author      = ">IZ:: / Glitchbane"
license     = "Same as Nmap"

local shortport = require "shortport"
local stdnse    = require "stdnse"

portrule = shortport.port_or_service(
  {21, 23, 3389, 5900},
  {"ftp", "telnet", "ms-wbt-server", "vnc"})

action = function(host, port)
  return stdnse.format_output(true, {
    note    = "Servicio potencialmente inseguro o legacy",
    service = port.service,
  })
end
