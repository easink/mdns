defmodule Mdns.Client do
  use GenServer
  require Logger

  @mdns_group {224, 0, 0, 251}
  @port Application.get_env(:mdns, :port, 5353)

  @query_packet %DNS.Record{
    header: %DNS.Header{},
    qdlist: []
  }

  defmodule State do
    defstruct devices: %{},
              udp: nil,
              handlers: [],
              queries: []
  end

  defmodule Device do
    defstruct ip: nil,
              services: [],
              service_ports: %{},
              domain: nil,
              payload: %{}
  end

  def start_link do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def query(namespace \\ "_services._dns-sd._udp.local") do
    GenServer.cast(__MODULE__, {:query, namespace})
  end

  def devices do
    GenServer.call(__MODULE__, :devices)
  end

  def start do
    GenServer.call(__MODULE__, :start)
  end

  def init(:ok) do
    {:ok, %State{}}
  end

  def handle_call(:start, _from, state) do
    udp_options = [
      :binary,
      broadcast: true,
      active: true,
      ip: {0, 0, 0, 0},
      ifaddr: {0, 0, 0, 0},
      add_membership: {@mdns_group, {0, 0, 0, 0}},
      multicast_if: {0, 0, 0, 0},
      multicast_loop: true,
      multicast_ttl: 32,
      reuseaddr: true
    ]

    {:ok, udp} = :gen_udp.open(@port, udp_options)
    {:reply, :ok, %State{state | udp: udp}}
  end

  def handle_call(:devices, _from, state) do
    {:reply, state.devices, state}
  end

  def handle_cast({:query, namespace}, state) do
    packet = %DNS.Record{
      @query_packet
      | qdlist: [
          %DNS.Query{domain: to_charlist(namespace), type: :ptr, class: :in}
        ]
    }

    p = DNS.Record.encode(packet)
    :gen_udp.send(state.udp, @mdns_group, @port, p)
    {:noreply, %State{state | queries: Enum.uniq([namespace | state.queries])}}
  end

  def handle_info({:udp, _socket, ip, _port, packet}, state) do
    {:noreply, handle_packet(ip, packet, state)}
  end

  def handle_packet(ip, packet, state) do
    record = DNS.Record.decode(packet)

    if record.header.qr,
      do: handle_response(ip, record, state),
      else: state
  end

  def handle_response(ip, record, state) do
    Logger.debug("mDNS got response: #{inspect(record)}")
    device = get_device(ip, record, state)

    devices =
      Enum.reduce(state.queries, %{other: []}, fn query, acc ->
        if Enum.any?(device.services, fn service -> String.ends_with?(service, query) end) do
          {namespace, devices} = create_namespace_devices(query, device, acc, state)
          Mdns.EventManager.notify({namespace, device})
          Logger.debug("mDNS device: #{inspect({namespace, device})}")
          devices
        else
          Map.merge(acc, state.devices)
        end
      end)

    %State{state | devices: devices}
  end

  def handle_device(%DNS.Resource{type: :ptr, domain: domain, data: data}, device) do
    %Device{
      device
      | services: Enum.uniq([to_string(data), to_string(domain) | device.services])
    }
  end

  def handle_device(%DNS.Resource{type: :a, domain: domain}, device) do
    %Device{device | domain: to_string(domain)}
  end

  def handle_device(%DNS.Resource{type: :txt, data: data}, device) do
    %Device{
      device
      | payload:
          Enum.reduce(data, device.payload, fn kv, acc ->
            case String.split(to_string(kv), "=", parts: 2) do
              [k, v] -> Map.put(acc, String.downcase(k), String.trim(v))
              _ -> device.payload
            end
          end)
    }
  end

  def handle_device(%DNS.Resource{type: :srv, domain: domain, data: {_p, _w, port, _t}}, device) do
    %Device{
      device
      | service_ports: Map.put(device.service_ports, to_string(domain), port)
    }
  end

  def handle_device(%DNS.Resource{}, device) do
    device
  end

  def handle_device({:dns_rr, _, _, _, _, _, _, _, _, _}, device) do
    device
  end

  def handle_device({:dns_rr_opt, _, _, _, _, _, _, _}, device) do
    device
  end

  def get_device(ip, record, state) do
    orig_device =
      Enum.concat(Map.values(state.devices))
      |> Enum.find(%Device{ip: ip}, fn device ->
        device.ip == ip
      end)

    Enum.reduce(record.anlist ++ record.arlist, orig_device, fn r, acc ->
      handle_device(r, acc)
    end)
  end

  def create_namespace_devices(query, device, devices, state) do
    namespace = String.to_atom(query)

    {namespace,
     if Enum.any?(Map.get(state.devices, namespace, []), fn dev -> dev.ip == device.ip end) do
       Map.merge(devices, %{namespace => merge_device(device, namespace, state)})
     else
       Map.merge(devices, %{namespace => [device | Map.get(state.devices, namespace, [])]})
     end}
  end

  def merge_device(device, namespace, state) do
    Enum.map(Map.get(state.devices, namespace, []), fn d ->
      if device.ip == d.ip,
        do: Map.merge(d, device),
        else: d
    end)
  end
end
