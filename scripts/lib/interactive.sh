#!/usr/bin/env bash

# Print an interactive menu to stderr and the selected machine value to stdout.
# Usage: narwhal_choose "Prompt" "default-value" "value|Label" ...
narwhal_choose() {
  local prompt="$1"
  local default_value="$2"
  shift 2
  local -a values=()
  local -a labels=()
  local entry=""
  local value=""
  local label=""
  for entry in "$@"; do
    value="${entry%%|*}"
    label="${entry#*|}"
    values+=("$value")
    labels+=("$label")
  done

  if [[ ${#values[@]} -eq 0 ]]; then
    echo "[ERROR] narwhal_choose requires at least one option" >&2
    return 2
  fi

  local selected=0
  local index=0
  for index in "${!values[@]}"; do
    if [[ "${values[$index]}" == "$default_value" ]]; then
      selected="$index"
      break
    fi
  done

  printf '\n%s\n' "$prompt" >&2
  for index in "${!values[@]}"; do
    printf '  %d) %s [%s]\n' "$((index + 1))" "${labels[$index]}" "${values[$index]}" >&2
  done

  local answer=""
  local normalized=""
  local resolved=""
  local numeric_value=0
  local key=""
  local sequence=""

  # stdout is captured by the caller, so stderr is the terminal used for UI.
  if [[ ! -t 0 || ! -t 2 ]]; then
    read -rp "请输入数字或名称（默认 $((selected + 1))）: " answer || answer=""
    answer="${answer:-$((selected + 1))}"
    normalized="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
    [[ "$normalized" == "y" ]] && normalized="yes"
    [[ "$normalized" == "n" ]] && normalized="no"
    if [[ "$normalized" =~ ^[0-9]+$ ]]; then
      numeric_value=$((10#$normalized))
      if (( numeric_value >= 1 && numeric_value <= ${#values[@]} )); then
        echo "${values[$((numeric_value - 1))]}"
        return
      fi
    fi
    for index in "${!values[@]}"; do
      if [[ "$(printf '%s' "${values[$index]}" | tr '[:upper:]' '[:lower:]')" == "$normalized" ]]; then
        echo "${values[$index]}"
        return
      fi
    done
    echo "[ERROR] 无效选择: $answer" >&2
    return 2
  fi

  printf '使用 ↑/↓ 移动，回车确认；也可输入数字或名称后回车。\n' >&2
  printf '> 当前: %d) %s [%s]' "$((selected + 1))" "${labels[$selected]}" "${values[$selected]}" >&2
  while true; do
    key=""
    if ! IFS= read -rsn1 key; then
      printf '\n' >&2
      echo "${values[$selected]}"
      return
    fi
    case "$key" in
      $'\x1b')
        sequence=""
        IFS= read -rsn2 -t 0.2 sequence || true
        case "$sequence" in
          '[A') selected=$(( (selected - 1 + ${#values[@]}) % ${#values[@]} )) ;;
          '[B') selected=$(( (selected + 1) % ${#values[@]} )) ;;
          *) continue ;;
        esac
        answer=""
        printf '\r\033[2K> 当前: %d) %s [%s]' "$((selected + 1))" "${labels[$selected]}" "${values[$selected]}" >&2
        ;;
      '')
        resolved=""
        if [[ -z "$answer" ]]; then
          resolved="${values[$selected]}"
        else
          normalized="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
          [[ "$normalized" == "y" ]] && normalized="yes"
          [[ "$normalized" == "n" ]] && normalized="no"
          if [[ "$normalized" =~ ^[0-9]+$ ]]; then
            numeric_value=$((10#$normalized))
            if (( numeric_value >= 1 && numeric_value <= ${#values[@]} )); then
              resolved="${values[$((numeric_value - 1))]}"
            fi
          else
            for index in "${!values[@]}"; do
              if [[ "$(printf '%s' "${values[$index]}" | tr '[:upper:]' '[:lower:]')" == "$normalized" ]]; then
                resolved="${values[$index]}"
                break
              fi
            done
          fi
        fi
        if [[ -n "$resolved" ]]; then
          printf '\n' >&2
          echo "$resolved"
          return
        fi
        printf '\r\033[2K> 无效选择: %s；请重新输入: ' "$answer" >&2
        answer=""
        ;;
      $'\x7f'|$'\b')
        answer="${answer%?}"
        printf '\r\033[2K> 输入: %s' "$answer" >&2
        ;;
      *)
        answer+="$key"
        printf '\r\033[2K> 输入: %s' "$answer" >&2
        ;;
    esac
  done
}
