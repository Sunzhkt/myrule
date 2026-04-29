import yaml
import os
import urllib.request

# 配置项
DLC_YAML_URL = "https://raw.githubusercontent.com/v2fly/domain-list-community/refs/heads/release/dlc.dat_plain.yml"
OUTPUT_DIR = "rules"  # 修改输出目录名为 rules，会更清晰

# 修复：自定义 YAML Loader，防止 0x0 被解析为整数 0
class SafeLoaderIgnoreInt(yaml.SafeLoader):
    pass

SafeLoaderIgnoreInt.add_implicit_resolver(
    u'tag:yaml.org,2002:str',
    yaml.SafeLoader.yaml_implicit_resolvers.get(None, []),
    None
)

def parse_rule(rule_str):
    if ':' not in rule_str:
        return None

    first_colon = rule_str.find(':')
    rule_type = rule_str[:first_colon]
    content = rule_str[first_colon+1:]

    # 清除属性 (如 :@ads, :@cn)
    attr_marker = ":@"
    if attr_marker in content:
        content = content.split(attr_marker)[0]

    shadowrocket_rule = None
    
    if rule_type == 'domain':
        shadowrocket_rule = f"DOMAIN-SUFFIX,{content}"
    elif rule_type == 'full':
        shadowrocket_rule = f"DOMAIN,{content}"
    elif rule_type == 'keyword':
        shadowrocket_rule = f"DOMAIN-KEYWORD,{content}"
    elif rule_type == 'regexp':
        shadowrocket_rule = f"URL-REGEX,{content}"
    elif rule_type == 'cidr':
        shadowrocket_rule = f"IP-CIDR,{content},no-resolve"
    
    return shadowrocket_rule

def main():
    print(f"正在下载 YAML 文件: {DLC_YAML_URL}")
    try:
        with urllib.request.urlopen(DLC_YAML_URL) as response:
            yaml_content = response.read().decode('utf-8')
    except Exception as e:
        print(f"下载失败: {e}")
        return

    print("正在解析 YAML (保留原始格式)...")
    try:
        # 使用自定义 Loader
        data = yaml.load(yaml_content, Loader=SafeLoaderIgnoreInt)
    except yaml.YAMLError as e:
        print(f"YAML 解析错误: {e}")
        return

    # 确保目录存在
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    lists = data.get('lists', [])
    print(f"共发现 {len(lists)} 个规则集，开始转换...")

    for item in lists:
        name = item.get('name')
        rules = item.get('rules', [])
        
        # 修正判断逻辑
        if name is None or name == "":
            continue
        
        name = str(name)
            
        filename = os.path.join(OUTPUT_DIR, f"{name}.list")
        count = 0
        
        with open(filename, 'w', encoding='utf-8') as f:
            for rule_str in rules:
                if not isinstance(rule_str, str):
                    continue
                sr_rule = parse_rule(rule_str)
                if sr_rule:
                    f.write(sr_rule + '\n')
                    count += 1
        
        # 如果没有规则，删除空文件
        if count == 0:
            if os.path.exists(filename):
                os.remove(filename)
        else:
            print(f"已生成: {filename} (共 {count} 条规则)")

    print("转换完成！")

if __name__ == "__main__":
    main()
