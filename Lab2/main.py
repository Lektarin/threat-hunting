def main():
	with open('dns_filtered', 'r') as fdns, open('hosts_filtered', 'r') as fhosts:
		dns_lines = fdns.readlines()		
		dns_l = [x for x in dns_lines if x.strip() and x.strip() != "-"]

		hosts_lines = fhosts.readlines()
		hosts_l = [x for x in hosts_lines if x.strip() and x.strip() != "-" and x.strip() != "#"]

		dns_set = set(dns_l)
		hosts_set = set(hosts_l)

		common_lines = dns_set.intersection(hosts_set)

	print(f"Общее количество строк в файле с dns: {len(dns_l)}")
	print(f"Количество нежелательных адресов: {len(common_lines)}")
	print(f"Процент нежелательного трафика: {round(len(common_lines) / len(dns_l) * 100, 2)}%")


if __name__ == "__main__":
	main()
