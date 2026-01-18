using System.Collections.Generic;
using CrossringUI.Models;
using Microsoft.Data.Sqlite;

namespace CrossringUI.Services;

public class DatabaseService
{
    private const string DbPath = @"C:\ProgramData\CROSSRING\database.db";

    public List<ProcessEventModel> GetRecentEvents(int limit = 100)
    {
        var events = new List<ProcessEventModel>();
        
        try
        {
            using var conn = new SqliteConnection($"Data Source={DbPath}");
            conn.Open();
            
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM process_events ORDER BY id DESC LIMIT @limit";
            cmd.Parameters.AddWithValue("@limit", limit);
            
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                events.Add(new ProcessEventModel
                {
                    Id = reader.GetInt64(0),
                    Timestamp = reader.GetString(1),
                    Pid = (uint)reader.GetInt32(3),
                    ImagePath = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    Decision = reader.IsDBNull(10) ? "Pending" : reader.GetString(10)
                });
            }
        }
        catch { }
        
        return events;
    }

    public List<MemoryAnomalyModel> GetRecentAnomalies(int limit = 100)
    {
        var anomalies = new List<MemoryAnomalyModel>();
        
        try
        {
            using var conn = new SqliteConnection($"Data Source={DbPath}");
            conn.Open();
            
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM memory_anomalies ORDER BY id DESC LIMIT @limit";
            cmd.Parameters.AddWithValue("@limit", limit);
            
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                anomalies.Add(new MemoryAnomalyModel
                {
                    Id = reader.GetInt64(0),
                    Timestamp = reader.GetString(1),
                    Pid = (uint)reader.GetInt32(2),
                    ProcessName = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    AnomalyType = reader.IsDBNull(7) ? "" : reader.GetString(7)
                });
            }
        }
        catch { }
        
        return anomalies;
    }

    public List<WhitelistEntryModel> GetWhitelistEntries()
    {
        var entries = new List<WhitelistEntryModel>();
        
        try
        {
            using var conn = new SqliteConnection($"Data Source={DbPath}");
            conn.Open();
            
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM whitelist ORDER BY id";
            
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                entries.Add(new WhitelistEntryModel
                {
                    Id = reader.GetInt64(0),
                    EntryType = reader.GetString(1),
                    Value = reader.GetString(2),
                    AddedTimestamp = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    Notes = reader.IsDBNull(4) ? "" : reader.GetString(4)
                });
            }
        }
        catch { }
        
        return entries;
    }
}
