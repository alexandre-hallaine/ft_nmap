char *get_type(int type)
{
	switch (type)
	{
	case OPEN:
		return "open";
	case CLOSED:
		return "closed";
	case FILTERED:
		return "filtered";
	case UNFILTERED:
		return "unfiltered";
	case UNEXPECTED:
		return "unexpected";
	case OPEN_FILTERED:
		return "open|filtered";
	default:
		return "unknown";
	}
}

void result()
{
	unsigned short amount[RESPONSE_MAX] = {0};
	for (unsigned short index = g_data.options.start_port; index <= g_data.options.end_port; index++)
		if (g_data.result[index] != UNSCANNED)
			amount[g_data.result[index]]++;

	t_reponse default_reponse = 0;
	for (t_reponse type = 0; type < RESPONSE_MAX; type++)
		if (amount[type] > amount[default_reponse])
			default_reponse = type;
	printf("Not shown: %d ports on state %s\n", amount[default_reponse], get_type(default_reponse));

	if (amount[default_reponse] == g_data.options.end_port - g_data.options.start_port + 1)
		return;

	printf("PORT\tSTATE\n");
	for (unsigned short index = g_data.options.start_port; index <= g_data.options.end_port; index++)
		if (g_data.result[index] != UNSCANNED && g_data.result[index] != default_reponse)
			printf("%d\t%s\n", index, get_type(g_data.result[index]));
}
