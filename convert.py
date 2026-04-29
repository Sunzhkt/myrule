import yaml
import os
import urllib.request

# 配置项
DLC_YAML_URL = "https://raw.githubusercontent.com/v2fly/domain-list-community/refs/heads/release/dlc.dat_plain.yml"
OUTPUT_DIR = "rules"  # 输出目录

# ==========================================
# 修复部分：自定义 YAML Loader
# 移除整数解析器，防止 0x0 被解析为 0
# ==========================================
class SafeLoaderIgnoreInt(yaml.SafeLoader):
    pass

# 遍历所有的隐式解析器，过滤掉整型解析器
# SafeLoader.yaml_implicit_resolvers 是一个字典，键是字符的首字符，值是(标签, 正则)列表
for key in SafeLoaderIgnoreInt.yaml_implicit_resolvers.keys():
    # 过滤掉 tag:yaml.org,2002:int 类型
    new_resolvers = []
    for tag, regexp in SafeLoaderIgnoreInt.yaml_implicit_resolvers[key]:
        if tag != 'tag:yaml.org,2002:int':
            new_resolvers.append((tag, regexp))
    SafeLoaderIgnoreInt.yaml_implicit_resolvers[key] = new_resolvers

def parse_rule(rule_str):
    """
    解析单条规则字符串，转换为 Shadowrocket 格式
    """
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

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    lists = data.get('lists', [])
    print(f"共发现 {len(lists)} 个规则集，开始转换...")

    for item in lists:
        name = item.get('name')
        rules = item.get('rules', [])
        
        # 修正判断逻辑：跳过 None 或空字符串，但保留 0
        if name is None or name == "":
            continue
        
        # 统一转为字符串
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
        
        if count > 0:
            print(f"已生成: {filename} (共 {count} 条规则)")
        else:
            if os.path.exists(filename):
                os.remove(filename)

    print("转换完成！")

if __name__ == "__main__":
    main()
