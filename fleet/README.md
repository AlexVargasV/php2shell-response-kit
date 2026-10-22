# Running the check on many servers

Two options. Both run [`scripts/php2shell-check.sh`](../scripts/php2shell-check.sh) read-only on each host and bring back `report.txt` and `ai-handoff.md`.

## Plain SSH (no extra tools)

```bash
cat > hosts.txt <<'EOF'
web1.example.com
deploy@web2.example.com
ssh://root@lms.example.com:2222
EOF
bash fleet/run-ssh.sh -H hosts.txt -R
```

Output: `php2shell-fleet-<date>/SUMMARY.md` with one row per host, plus a folder per host with the report, the AI hand-off and the evidence.

- Uses key-based SSH (`BatchMode=yes`); hosts that would prompt for a password are reported as unreachable.
- Uses `sudo -n` when the user has passwordless sudo; otherwise runs unprivileged and says so.
- Uploads the script by streaming it over SSH and deletes it afterwards. The evidence folder stays in `/tmp/php2shell-triage` on the host too.

## Ansible

```bash
cp fleet/ansible/inventory.example.ini fleet/ansible/inventory.ini   # edit it
ansible-playbook -i fleet/ansible/inventory.ini fleet/ansible/php2shell-check.yml
ansible-playbook -i fleet/ansible/inventory.ini fleet/ansible/php2shell-check.yml -e redact=false -e quick=true
```

Output: `fleet/ansible/results/<host>/` and `fleet/ansible/results/SUMMARY.txt`.

## Then

Give an AI assistant [`ai/CONTEXT.md`](../ai/CONTEXT.md) plus the `ai-handoff.md` files and use the **Multiple servers** prompt in [`ai/PROMPTS.md`](../ai/PROMPTS.md). Keep conclusions per host, and look for cross-host risks: shared database passwords, the same deploy key on several servers, the same vulnerable plugin everywhere.

## Patch the fleet (after review)

The kit deliberately does not ship an automatic "patch everything" playbook: PHP upgrades restart services and can break applications. A minimal, reviewable pattern for Debian/Ubuntu hosts using distro packages:

```yaml
- hosts: php_servers
  become: true
  serial: 1                      # one host at a time
  tasks:
    - ansible.builtin.apt: { name: "php*", state: latest, only_upgrade: true, update_cache: true }
    - ansible.builtin.shell: systemctl restart 'php*-fpm' apache2 2>/dev/null || true
    - ansible.builtin.command: php -v
      register: v
      changed_when: false
    - ansible.builtin.debug: { var: v.stdout_lines[0] }
```

Verify each host afterwards through the **web** SAPI (phpinfo or your health endpoint), not just `php -v`.
