#!/usr/bin/env bash

tempfiles=()

function rollback()
{
  for tempfile in "${tempfiles[@]}"; do
    rm "$tempfile"
  done
}

trap rollback EXIT


inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host
EOS

config_file="$(mktemp --suffix .json)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
{
  "from": "me",
  "to": { "host": "host" }
}
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami) => $(whoami)@host
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from: me
to:
  host: host
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami) => $(whoami)@host
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  public_key: ssh-dss AAAAB3NzaC1kc3MAAACBAKwt6Lwj+SGy6ER/O7vTcyj0K6RiMV/ZM5F9vvFAV8OkBUVyg+GL0Xgt2TC93GuON0S05B5Qz8rLJrq/c28DiNYKL+yIGozWWrDMtBuvAExmT6bi5EbFrVIz6TAOoNUiEhgRDf0YDM3HZEtMycPFjdemHC0urLTyhYmGmHx6a0FLAAAAFQCktTmD8ab6YcBL4cgRgJBrT/dyqQAAAIAv30C/E+LBD19QNqruEmAnvF+CI2+nk/2d0DVEpwZDXqvgeUN7Am69QzF/8F6pKlxn1pWl64qAXLhRkI27e4qWNkxBwrB3CXYpYK/waAh57OmCTNoJ37KRpSP9Y3lYLB4d/VKXxPJw7wMN+1fYIcCtkcoAI5kD2fKE+iRvoimPQQAAAIEAq+o/Z4T4yCuvnU/0anLvmuPZn8HK5d454tBxIc/k+6hw7IYnpwxFMmeGalpSvd/Y17y6eTfPBrCoAtN5FW+FeBvIZ74QyrwPnTuLP4d5SCPxHWZ5lMiBDwJNgvPtjA3n0FfAPNe4H9p59RHI50XvYm7qIioh93IR7d6GhgXp/Ac= cryolite@test
to:
  host: host
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
1024 SHA256:hgwAiVnGEdelVzIRnRiLaj4LXYV8ewT5yvU0YaK083Q cryolite@test (DSA) => $(whoami)@host
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  public_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCz7O+t2YVYWvSgaV/fgXeGzmzSgJ6eETBUe6uEceLm6NmCcsF8emXa3U/571N/CiucH6Ryj2OyjJCpw93ay3UJMBvbPW1rJaKG5a2IE8lVpRLtrEcj9WH+cXcjpFVpHLV++Mewgg9qaCxmfHosPbLAEaQjGHWhTE8isOQOwu+oLA35dmJMttqOaMzNJojlPHf2AGuYpZ3RVM91y1vYEEjmR7QIuO55F8SbuGDZrPPz7Uj26Eg1/WGnFmYRM2TjNhQnlMGN9YkwRuQVocu3odqZzQJhFIRNPUjeQ8SngXk8uIy9XMHwlLc5a4JmpRvWl+NdTJPXTKlItH21npUnUkA7 cryolite@test
to:
  host: host
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
2048 SHA256:nkyPre+S1fs7KtNHiBkE6Hwro9Cx3Q5gunUk5L/9kGE cryolite@test (RSA) => $(whoami)@host
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  public_key: ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDEyhMkWyM4ErYqCdBpv4+sJVHeGjlU5kvgav9semg0LXH7SgWjIRFBZ/yrgd4lL32LqDGAu+9Z8g0/dvL1IjXo= cryolite@test
to:
  host: host
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
256 SHA256:KXvf3UWu3sc2pA7GP87d5w29I+KXz1a0c2vxtbbBaao cryolite@test (ECDSA) => $(whoami)@host
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  public_key: ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBMkrJwwi/J99LJsvancrEmjjlG/kjw767GXB4v3OnvhIQ1HovAQ3SBIRJEY2nnevb/DIAkCfvcrrIm8TvQyQUcdC8zrqpP0d8dQSneADoA2SEEDVHyK73v3I/5NRJv8LgQ== cryolite@test
to:
  host: host
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
384 SHA256:1/8wd0BpeJ+MTFp5bXfAN9+T240DIZ2tgEPwWqORDfM cryolite@test (ECDSA) => $(whoami)@host
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  public_key: ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAG+Arucmfyn5nnSTw7Z1gqjr0+szNBOYF7WC7Bq/Gayy+LoggC/4yp2OLJa7HQhgfWLE6lwfrmkhWnpJsZE7RFPrQB46ODSGC+216vNSCTSILZdNZqSlrtBQKWjpmhNZGVET3yHRYnYj6LUgDBj/IFxlhIT+xkMkPXuKOv0wtYUJIUZZg== cryolite@test
to:
  host: host
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
521 SHA256:JdCU51vqcwjMEYftBPuq4bNQdvqRjBRQM/PE7VftB30 cryolite@test (ECDSA) => $(whoami)@host
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  public_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlChLERZeLBY41U8KexwCuuO0RCE44pKUMuIe2YKMUR cryolite@test
to:
  host: host
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
256 SHA256:Wp9/CHm5apW0dyNcTs0PHSi12QOFRCs272H5yj+x8zI cryolite@test (ED25519) => $(whoami)@host
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_host=realhost
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@realhost => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_port=2222
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1:2222 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  host_public_key: ssh-dss AAAAB3NzaC1kc3MAAACBAKwt6Lwj+SGy6ER/O7vTcyj0K6RiMV/ZM5F9vvFAV8OkBUVyg+GL0Xgt2TC93GuON0S05B5Qz8rLJrq/c28DiNYKL+yIGozWWrDMtBuvAExmT6bi5EbFrVIz6TAOoNUiEhgRDf0YDM3HZEtMycPFjdemHC0urLTyhYmGmHx6a0FLAAAAFQCktTmD8ab6YcBL4cgRgJBrT/dyqQAAAIAv30C/E+LBD19QNqruEmAnvF+CI2+nk/2d0DVEpwZDXqvgeUN7Am69QzF/8F6pKlxn1pWl64qAXLhRkI27e4qWNkxBwrB3CXYpYK/waAh57OmCTNoJ37KRpSP9Y3lYLB4d/VKXxPJw7wMN+1fYIcCtkcoAI5kD2fKE+iRvoimPQQAAAIEAq+o/Z4T4yCuvnU/0anLvmuPZn8HK5d454tBxIc/k+6hw7IYnpwxFMmeGalpSvd/Y17y6eTfPBrCoAtN5FW+FeBvIZ74QyrwPnTuLP4d5SCPxHWZ5lMiBDwJNgvPtjA3n0FfAPNe4H9p59RHI50XvYm7qIioh93IR7d6GhgXp/Ac= root@test
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  host_public_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCz7O+t2YVYWvSgaV/fgXeGzmzSgJ6eETBUe6uEceLm6NmCcsF8emXa3U/571N/CiucH6Ryj2OyjJCpw93ay3UJMBvbPW1rJaKG5a2IE8lVpRLtrEcj9WH+cXcjpFVpHLV++Mewgg9qaCxmfHosPbLAEaQjGHWhTE8isOQOwu+oLA35dmJMttqOaMzNJojlPHf2AGuYpZ3RVM91y1vYEEjmR7QIuO55F8SbuGDZrPPz7Uj26Eg1/WGnFmYRM2TjNhQnlMGN9YkwRuQVocu3odqZzQJhFIRNPUjeQ8SngXk8uIy9XMHwlLc5a4JmpRvWl+NdTJPXTKlItH21npUnUkA7 cryolite@test
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  host_public_key: ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDEyhMkWyM4ErYqCdBpv4+sJVHeGjlU5kvgav9semg0LXH7SgWjIRFBZ/yrgd4lL32LqDGAu+9Z8g0/dvL1IjXo= cryolite@test
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  host_public_key: ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBMkrJwwi/J99LJsvancrEmjjlG/kjw767GXB4v3OnvhIQ1HovAQ3SBIRJEY2nnevb/DIAkCfvcrrIm8TvQyQUcdC8zrqpP0d8dQSneADoA2SEEDVHyK73v3I/5NRJv8LgQ== cryolite@test
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  host_public_key: ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAG+Arucmfyn5nnSTw7Z1gqjr0+szNBOYF7WC7Bq/Gayy+LoggC/4yp2OLJa7HQhgfWLE6lwfrmkhWnpJsZE7RFPrQB46ODSGC+216vNSCTSILZdNZqSlrtBQKWjpmhNZGVET3yHRYnYj6LUgDBj/IFxlhIT+xkMkPXuKOv0wtYUJIUZZg== cryolite@test
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  host_public_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlChLERZeLBY41U8KexwCuuO0RCE44pKUMuIe2YKMUR cryolite@test
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_user=user
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
user@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  login_name: user
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
user@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_user=user1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  login_name: user2
to:
  host: host2
EOS

diff -q <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
user2@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_ssh_pass=password
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
to:
  host: host2
EOS

diff <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 cryolite_password=password
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  login_password: {variable: cryolite_password}
to:
  host: host2
EOS

diff <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_ssh_pass=password1 cryolite_password=password2
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  login_password: {variable: cryolite_password}
to:
  host: host2
EOS

diff <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_become_user=user
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
to:
  host: host2
EOS

diff <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
user@host1 (sudo by $(whoami)) => $(whoami)@host2
EOS
(( $? != 0 )) && cat "$inventory_file" "$config_file"

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  sudo_username: user
to:
  host: host2
EOS

diff <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
user@host1 (sudo by $(whoami)) => $(whoami)@host2
EOS
(( $? != 0 )) && cat "$inventory_file" "$config_file"

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_become_user=user1
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  sudo_username: user2
to:
  host: host2
EOS

diff <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
user2@host1 (sudo by $(whoami)) => $(whoami)@host2
EOS
(( $? != 0 )) && cat "$inventory_file" "$config_file"

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_become_pass=password
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
to:
  host: host2
EOS

diff <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS
(( $? != 0 )) && cat "$inventory_file" "$config_file"

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 cryolite_password=password
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  sudo_password: {variable: cryolite_password}
to:
  host: host2
EOS

diff <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS
(( $? != 0 )) && cat "$inventory_file" "$config_file"

###############################################################################

inventory_file="$(mktemp)"
tempfiles+=("$inventory_file")
cat >"$inventory_file" <<'EOS'
host1 ansible_become_pass=password1 cryolite_password=password2
host2
EOS

config_file="$(mktemp --suffix .yaml)"
config_file+=("$config_file")
tempfiles+=("$config_file")
cat >"$config_file" <<'EOS'
from:
  host: host1
  sudo_password: {variable: cryolite_password}
to:
  host: host2
EOS

diff <(./ansible-ssh-prepare.py -n -i "$inventory_file" "$config_file") - <<EOS
$(whoami)@host1 => $(whoami)@host2
EOS
(( $? != 0 )) && cat "$inventory_file" "$config_file"
