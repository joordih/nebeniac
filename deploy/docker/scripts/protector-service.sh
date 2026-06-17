#!/bin/bash

INPUT_DIR="/app/input"
OUTPUT_DIR="/app/output"
TEMP_DIR="/app/temp"
PROCESSED_DIR="/app/input/processed"

mkdir -p "$INPUT_DIR" "$OUTPUT_DIR" "$TEMP_DIR" "$PROCESSED_DIR"

PROTECTOR_JAR=""
for jar_path in "/app/shared/protector.jar" "/app/protector-1.0-SNAPSHOT.jar" "/app/target/protector-1.0-SNAPSHOT.jar" "/app/protector.jar"; do
    if [ -f "$jar_path" ]; then
        PROTECTOR_JAR="$jar_path"
        echo "Protector JAR found at: $PROTECTOR_JAR"
        break
    fi
done

if [ -z "$PROTECTOR_JAR" ]; then
    echo "ERROR: protector.jar not found in any expected location"
    echo "Searched locations:"
    echo "  - /app/shared/protector.jar"
    echo "  - /app/protector-1.0-SNAPSHOT.jar"
    echo "  - /app/target/protector-1.0-SNAPSHOT.jar"
    echo "  - /app/protector.jar"
    exit 1
fi

echo "Protector service started"
echo "Watching: $INPUT_DIR"
echo "Output: $OUTPUT_DIR"
echo "Using JAR: $PROTECTOR_JAR"

process_jar() {
    local input_file="$1"
    local license_key="$2"
    local plugin_id="$3"
    local target_packages="$4"

    echo "Processing: $input_file"
    echo "License: $license_key"
    echo "Plugin ID: $plugin_id"
    echo "Packages: $target_packages"

    local base_name=$(basename "$input_file" .jar)
    local output_file="$OUTPUT_DIR/${base_name}-encrypted.jar"

    if [ -n "$license_key" ] && [ -n "$plugin_id" ]; then
        if [ -n "$target_packages" ]; then
            echo "Running: java -jar $PROTECTOR_JAR $input_file $output_file $license_key $plugin_id $target_packages"
            java -jar "$PROTECTOR_JAR" "$input_file" "$output_file" "$license_key" "$plugin_id" "$target_packages"
        else
            echo "Running: java -jar $PROTECTOR_JAR $input_file $output_file $license_key $plugin_id"
            java -jar "$PROTECTOR_JAR" "$input_file" "$output_file" "$license_key" "$plugin_id"
        fi
    else
        echo "Running: java -jar $PROTECTOR_JAR $input_file $output_file"
        java -jar "$PROTECTOR_JAR" "$input_file" "$output_file"
    fi

    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "Processing successful: $output_file"

        mv "$input_file" "$PROCESSED_DIR/"

        cat > "$OUTPUT_DIR/${base_name}-encrypted.meta" << EOF
{
    "originalFile": "$(basename "$input_file")",
    "protectedFile": "$(basename "$output_file")",
    "licenseKey": "$license_key",
    "pluginId": "$plugin_id",
    "processedAt": "$(date -Iseconds)",
    "status": "success"
}
EOF
    else
        echo "Error processing: $input_file (exit code: $exit_code)"

        cat > "$OUTPUT_DIR/${base_name}-error.meta" << EOF
{
    "originalFile": "$(basename "$input_file")",
    "licenseKey": "$license_key",
    "pluginId": "$plugin_id",
    "processedAt": "$(date -Iseconds)",
    "status": "error",
    "exitCode": $exit_code
}
EOF
    fi
}

process_config_file() {
    local config_file="$1"

    echo "Processing config: $config_file"

    local jar_file=$(jq -r '.jarFile' "$config_file")
    local license_key=$(jq -r '.licenseKey' "$config_file")
    local plugin_id=$(jq -r '.pluginId' "$config_file")
    local target_packages=$(jq -r '.targetPackages' "$config_file")

    local full_jar_path="$INPUT_DIR/$jar_file"
    if [ -f "$full_jar_path" ]; then
        process_jar "$full_jar_path" "$license_key" "$plugin_id" "$target_packages"
    else
        echo "ERROR: JAR file not found: $full_jar_path"
    fi

    mv "$config_file" "$PROCESSED_DIR/"
}

echo "Processing existing files..."
for file in "$INPUT_DIR"/*.jar; do
    if [ -f "$file" ]; then
        process_jar "$file" "" ""
    fi
done

for file in "$INPUT_DIR"/*.json; do
    if [ -f "$file" ]; then
        process_config_file "$file"
    fi
done

echo "Starting file watch..."
inotifywait -m -e close_write -e moved_to "$INPUT_DIR" --format '%w%f %e' |
while read file event; do
    echo "Event detected: $event on $file"

    sleep 1

    if [[ "$file" == *.jar ]]; then
        process_jar "$file" "" ""
    elif [[ "$file" == *.json ]]; then
        process_config_file "$file"
    else
        echo "Unsupported file type: $file"
    fi
done
