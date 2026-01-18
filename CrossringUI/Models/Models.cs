namespace CrossringUI.Models;

public class ProcessEventModel
{
    public long Id { get; set; }
    public string Timestamp { get; set; } = "";
    public uint Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string ImagePath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public string Hash { get; set; } = "";
    public bool IsSigned { get; set; }
    public string Signer { get; set; } = "";
    public string Decision { get; set; } = "";
}

public class MemoryAnomalyModel
{
    public long Id { get; set; }
    public string Timestamp { get; set; } = "";
    public uint Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string AnomalyType { get; set; } = "";
    public ulong RegionSize { get; set; }
    public string Protection { get; set; } = "";
}

public class NetworkEventModel
{
    public long Id { get; set; }
    public string Timestamp { get; set; } = "";
    public uint Pid { get; set; }
    public string LocalAddr { get; set; } = "";
    public ushort LocalPort { get; set; }
    public string RemoteAddr { get; set; } = "";
    public ushort RemotePort { get; set; }
    public string Protocol { get; set; } = "";
}

public class WhitelistEntryModel
{
    public long Id { get; set; }
    public string EntryType { get; set; } = "";
    public string Value { get; set; } = "";
    public string AddedTimestamp { get; set; } = "";
    public string Notes { get; set; } = "";
}
