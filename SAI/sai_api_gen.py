#!/usr/bin/env python3

try:
    import os
    import json
    import argparse
    from git import Repo
    from jinja2 import Template, Environment, FileSystemLoader
except ImportError as ie:
    print("Import failed for " + ie.name)
    exit(1)

NAME_TAG = 'name'
TABLES_TAG = 'tables'
BITWIDTH_TAG = 'bitwidth'
ACTIONS_TAG = 'actions'
PREAMBLE_TAG = 'preamble'
OTHER_MATCH_TYPE_TAG = 'otherMatchType'
MATCH_TYPE_TAG = 'matchType'
PARAMS_TAG = 'params'
ACTION_REFS_TAG = 'actionRefs'
MATCH_FIELDS_TAG = 'matchFields'
NOACTION = 'NoAction'

def get_sai_key_type(key_size, key_header, key_field):
    if key_size == 1:
        return 'bool'
    elif key_size <= 8:
        return 'sai_uint8_t'
    elif key_size <= 16:
        return 'sai_uint16_t'
    elif key_size == 32 and ('addr' in key_field or 'ip' in key_header):
        return 'sai_ip_address_t'
    elif key_size <= 32:
        return 'sai_uint32_t'
    elif key_size == 48 and ('addr' in key_field or 'mac' in key_header):
        return 'sai_mac_t'
    elif key_size <= 64:
        return 'sai_uint64_t'
    else:
        raise ValueError(f'key_size={key_size} is not supported')


def get_sai_lpm_type(key_size, key_header, key_field):
    if key_size == 32 and ('addr' in key_field or 'ip' in key_header):
        return 'sai_ip_prefix_t'
    raise ValueError(f'key_size={key_size}, key_header={key_header}, and key_field={key_field} is not supported')


def get_sai_list_type(key_size, key_header, key_field):
    if key_size <= 8:
        return 'sai_u8_list_t'
    elif key_size <= 16:
        return 'sai_u16_list_t'
    elif key_size == 32 and ('addr' in key_field or 'ip' in key_header):
        return 'sai_ip_address_list_t'
    elif key_size <= 32:
        return 'sai_u32_list_t'
    elif key_size <= 64:
        return 'sai_u64_list_t'
    raise ValueError(f'key_size={key_size} is not supported')


def get_sai_range_list_type(key_size, key_header, key_field):
    if key_size <= 8:
        return 'sai_u8_range_list_t'
    elif key_size <= 16:
        return 'sai_u16_range_list_t'
    elif key_size == 32 and ('addr' in key_field or 'ip' in key_header):
        return 'sai_ipaddr_range_list_t'
    elif key_size <= 32:
        return 'sai_u32_range_list_t'
    elif key_size <= 64:
        return 'sai_u64_range_list_t'
    raise ValueError(f'key_size={key_size} is not supported')


def get_sai_key_data(key):
    sai_key_data = dict()
    full_key_name, sai_key_name = key[NAME_TAG].split(':')
    key_tuple = full_key_name.split('.')
    if len(key_tuple) == 3:
        key_struct, key_header, key_field = key_tuple
    else:
        key_header, key_field = key_tuple
    sai_key_data['sai_key_name'] = sai_key_name

    key_size = key[BITWIDTH_TAG]
    
    if OTHER_MATCH_TYPE_TAG in key:
        sai_key_data['match_type'] =  key[OTHER_MATCH_TYPE_TAG].lower()
    elif MATCH_TYPE_TAG in key:
        sai_key_data['match_type'] =  key[MATCH_TYPE_TAG].lower()
    else:
        raise ValueError(f'No valid match tag found')

    if sai_key_data['match_type'] == 'exact':
        sai_key_data['sai_key_type'] = get_sai_key_type(key_size, key_header, key_field)
    elif sai_key_data['match_type'] == 'lpm':
        sai_key_data['sai_lpm_type'] = get_sai_lpm_type(key_size, key_header, key_field)
    elif sai_key_data['match_type'] == 'list':
        sai_key_data['sai_list_type'] = get_sai_list_type(key_size, key_header, key_field)
    elif sai_key_data['match_type'] == 'range_list':
        sai_key_data['sai_range_list_type'] = get_sai_range_list_type(key_size, key_header, key_field)
    else:
        raise ValueError(f"match_type={sai_key_data['match_type']} is not supported")

    return sai_key_data


def extract_action_data(program):
    action_data = {}
    for action in program[ACTIONS_TAG]:
        #print(action)
        preable = action[PREAMBLE_TAG]
        id = preable['id']
        name = preable[NAME_TAG].split('.')[-1]
        params = []
        if PARAMS_TAG in action:
            for p in action[PARAMS_TAG]:
                param = dict()
                param['id'] = p['id']
                param[NAME_TAG] = p[NAME_TAG]
                param['type'] = get_sai_key_type(int(p[BITWIDTH_TAG]), p[NAME_TAG], p[NAME_TAG])
                params.append(param)
        action_data[id] = {'id': id, NAME_TAG: name, PARAMS_TAG: params}
    return action_data


def generate_sai_api(program, ignore_tables):
    sai_api = dict()
    all_actions = extract_action_data(program)
    tables = program[TABLES_TAG]
    sai_tables = []
    for table in tables:
        sai_table_data = dict()
        sai_table_data['keys'] = []
        sai_table_data[ACTIONS_TAG] = []
        table_control, table_name = table[PREAMBLE_TAG][NAME_TAG].split('.', 1)
        sai_table_data[NAME_TAG] = table_name.replace('.' , '_')

        if sai_table_data[NAME_TAG] in ignore_tables:
            continue

        for key in table[MATCH_FIELDS_TAG]:
            sai_table_data['keys'].append(get_sai_key_data(key))

        for action in table[ACTION_REFS_TAG]:
            action_id = action["id"]
            if all_actions[action_id][NAME_TAG] != NOACTION:
                sai_table_data[ACTIONS_TAG].append(all_actions[action_id])

        if len(sai_table_data['keys']) == 1 and sai_table_data['keys'][0]['sai_key_name'] == (table_name.split('.')[-1] + '_id'):
            sai_table_data['is_object'] = 'true'
            # Object ID itself is a key
            sai_table_data['keys'] = []
        elif len(sai_table_data['keys']) > 5:
            sai_table_data['is_object'] = 'true'
        else:
            sai_table_data['is_object'] = 'false'
            sai_table_data[NAME_TAG] = sai_table_data[NAME_TAG] + '_entry'

        sai_tables.append(sai_table_data)

    sai_api[TABLES_TAG] = sai_tables
    return sai_api


def write_sai_files(sai_api):
    # The main file
    with open('saiapi.h.j2', 'r') as sai_header_tm_file:
        sai_header_tm_str = sai_header_tm_file.read()

    env = Environment(loader=FileSystemLoader('.'), trim_blocks=True, lstrip_blocks=True)
    sai_header_tm = env.get_template('saiapi.h.j2')
    sai_header_str = sai_header_tm.render(sai_api = sai_api)

    with open('./SAI/experimental/saiexperimental' + sai_api['app_name'] + '.h', 'w') as o:
        o.write(sai_header_str)

    # The SAI Extensions
    with open('./SAI/experimental/saiextensions.h', 'r') as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        if 'Add new experimental APIs above this line' in line:
            new_lines.append('    SAI_API_' + sai_api['app_name'].upper() + ',\n\n')
        if 'new experimental object type includes' in line:
            new_lines.append(line)
            new_lines.append('#include "saiexperimental' + sai_api['app_name'] + '.h"\n')
            continue

        new_lines.append(line)

    with open('./SAI/experimental/saiextensions.h', 'w') as f:
        f.write(''.join(new_lines))

    # The SAI Type Extensions
    with open('./SAI/experimental/saitypesextensions.h', 'r') as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        if 'Add new experimental object types above this line' in line:
            for table in sai_api[TABLES_TAG]:
                new_lines.append('    SAI_OBJECT_TYPE_' + table[NAME_TAG].upper() + ',\n\n')

        new_lines.append(line)

    with open('./SAI/experimental/saitypesextensions.h', 'w') as f:
        f.write(''.join(new_lines))

    # The SAI object struct for entries
    with open('./SAI/inc/saiobject.h', 'r') as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        if 'Add new experimental entries above this line' in line:
            for table in sai_api[TABLES_TAG]:
                if table['is_object'] == 'false':
                    new_lines.append('    /** @validonly object_type == SAI_OBJECT_TYPE_' + table[NAME_TAG].upper() + ' */\n')
                    new_lines.append('    sai_' + table[NAME_TAG] + '_t ' + table[NAME_TAG] + ';\n\n')
        if 'new experimental object type includes' in line:
            new_lines.append(line)
            new_lines.append('#include "../experimental/saiexperimental' + sai_api['app_name'] + '.h"\n')
            continue

        new_lines.append(line)

    with open('./SAI/inc/saiobject.h', 'w') as f:
        f.write(''.join(new_lines))



# CLI
parser = argparse.ArgumentParser(description='P4 SAI API generator')
parser.add_argument('filepath', type=str, help='Path to P4 program RUNTIME JSON file')
parser.add_argument('apiname', type=str, help='Name of the new SAI API')
parser.add_argument('--print-sai-lib', type=bool)
parser.add_argument('--sai-git-url', type=str, default='https://github.com/Opencomputeproject/SAI')
parser.add_argument('--ignore-tables', type=str, default='', help='Comma separated list of tables to ignore')
parser.add_argument('--sai-git-branch', type=str, default='master')
args = parser.parse_args()

if not os.path.isfile(args.filepath):
    print('File ' + args.filepath + ' does not exist')
    exit(1)

if os.path.exists('./SAI'):
    print('Directory ./SAI already exists. Please remove in order to proceed')
    exit(1)


# Get SAI dictionary from P4 dictionary
print("Generating SAI API...")
with open(args.filepath) as json_program_file:
    json_program = json.load(json_program_file)

sai_api = generate_sai_api(json_program, args.ignore_tables.split(','))
sai_api['app_name'] = args.apiname

# Clone a clean SAI repo
print("Cloning SAI repository...")
Repo.clone_from(args.sai_git_url, './SAI', branch=args.sai_git_branch)

# Write SAI dictionary into SAI API headers
write_sai_files(sai_api)

if args.print_sai_lib:
    print(json.dumps(sai_api, indent=2))
