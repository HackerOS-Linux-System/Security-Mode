# src/auditing-logging.cr
# Auditing and Logging tool for Security Mode, written in Crystal.
# Handles write-only logs, rotation, and optional forwarding.
# Logs are stored in ~/.hackeros/Security-Mode/logs/security.log
# Communication can use JSON in /tmp/Security-Mode/logs.json for batch logging.
# CLI commands: append <message>, rotate, forward <target>

require "json"
require "file_utils"
require "process"

# Define log directory and file
LOG_DIR = File.expand_path("~/.hackeros/Security-Mode/logs")
LOG_FILE = File.join(LOG_DIR, "security.log")
MAX_LOG_SIZE = 10 * 1024 * 1024 # 10 MB

# Ensure log directory exists
def ensure_log_dir
  FileUtils.mkdir_p(LOG_DIR) unless Dir.exists?(LOG_DIR)
end

# Append a message to the log file with timestamp
def append_log(message : String)
  ensure_log_dir
  timestamp = Time.utc.to_s("%Y-%m-%d %H:%M:%S UTC")
  log_entry = "[#{timestamp}] #{message}\n"
  File.open(LOG_FILE, "a") do |f|
    f.write(log_entry.to_slice)
  end
  check_rotate
end

# Check if log needs rotation
def check_rotate
  if File.exists?(LOG_FILE) && File.size(LOG_FILE) > MAX_LOG_SIZE
    rotate_log
  end
end

# Rotate the log file
def rotate_log
  if File.exists?(LOG_FILE)
    timestamp = Time.utc.to_s("%Y%m%d%H%M%S")
    rotated_file = File.join(LOG_DIR, "security_#{timestamp}.log")
    FileUtils.mv(LOG_FILE, rotated_file)
    puts "Rotated log to #{rotated_file}"
  end
end

# Forward logs to a target (simulated, e.g., file or SIEM endpoint)
# For simplicity, forward to another file or print
def forward_logs(target : String)
  if File.exists?(LOG_FILE)
    content = File.read(LOG_FILE)
    if target.starts_with?("file:")
      target_file = target[5..-1].strip
      File.write(target_file, content)
      puts "Forwarded logs to #{target_file}"
    else
      # Simulate SIEM forward, e.g., via HTTP or something, but no internet, so just print
      puts "Forwarding to SIEM #{target}:"
      puts content
    end
  else
    puts "No log file to forward."
  end
end

# Process logs from JSON file if present
def process_json_logs
  tmp_dir = "/tmp/Security-Mode"
  json_path = File.join(tmp_dir, "logs.json")
  if File.exists?(json_path)
    json_str = File.read(json_path)
    data = JSON.parse(json_str).as_h
    if logs = data["logs"]?
      logs.as_a.each do |log|
        append_log(log.as_s)
      end
      puts "Processed logs from JSON"
      File.delete(json_path)
    end
  end
end

# Main CLI parser
def main
  process_json_logs # Always check for JSON logs first

  if ARGV.empty?
    puts "Usage: auditing-logging <command> [args]"
    puts "Commands:"
    puts "  append <message>  - Append a message to the log"
    puts "  rotate            - Rotate the log file"
    puts "  forward <target>  - Forward logs to target (file:path or siem:url)"
    exit(1)
  end

  command = ARGV[0].downcase

  case command
  when "append"
    if ARGV.size > 1
      message = ARGV[1..-1].join(" ")
      append_log(message)
      puts "Appended log: #{message}"
    else
      puts "Missing message for append command."
    end
  when "rotate"
    rotate_log
  when "forward"
    if ARGV.size > 1
      forward_logs(ARGV[1])
    else
      puts "Missing target for forward command."
    end
  else
    puts "Unknown command: #{command}"
  end
end

main if __FILE__ == Process.executable_path
