#include <cstdio>
#include <cstring>

int check_arch(char* s)
{
	int len = strlen(s);
	int x = 0,y = 0;
	char jmptbl[] = "jmptbl";
	char insns[] = "insns";
	char funcs[] = "funcs";
	for(int i = 0;i < len;i++)
	{
		int cnt = 0;
		for(int j = 0;j + i < len;j++)
			if(s[i + j] == jmptbl[j])
				cnt++;
			else
				break;
		if(cnt == 6)
		{
			y = 8;
			for(int j = i + 7;j  + 1 < len;j++)
			{
				if(s[j] == 'm' && s[j + 1] == 't')
					y += 1;
				else if(s[j] == 'm' && s[j + 1] == 'i')
					y += 3;
				else if(s[j] == 'a' && s[j + 1] == 'a')
					y += 2;
				else if(s[j] == 'a' && s[j + 1] == 'r')
					y += 0;
				break;
			}
			for(int j = i + 7;j + 1 < len;j++)
				if(s[j] == '/')
				{
					int k = j + 1;
					if(s[k] == 'o')
						x = 0;
					else if(s[k] == 'g')
						x = 1;
					else if(s[k] == 'a')
						x = 2;
					else if(s[k] == 'r')
						x = 3;
					else if(s[k] == 'i')
						x = 4;
					else if(s[k] == 'n')
						x = 5;
					break;
				}
			break;
		}
		cnt = 0;
		for(int j = 0;j + i < len;j++)
			if(s[i + j] == insns[j])
				cnt++;
			else
				break;
		if(cnt == 5)
		{
			y = 0;
			for(int j = i + 6;j  + 1 < len;j++)
			{
				if(s[j] == 'm' && s[j + 1] == 't')
					y += 1;
				else if(s[j] == 'm' && s[j + 1] == 'i')
					y += 3;
				else if(s[j] == 'a' && s[j + 1] == 'a')
					y += 2;
				else if(s[j] == 'a' && s[j + 1] == 'r')
					y += 0;
				break;
			}
			cnt = 0;
			for(int j = i + 6;j + 1 < len;j++)
				if(s[j] == '/')
				{	
					int k = j + 1;
					if(s[k] == 'o')
						x = 0;
					else if(s[k] == 'g')
						x = 1;
					else if(s[k] == 'a')
						x = 2;
					else if(s[k] == 'r')
						x = 3;
					else if(s[k] == 'i')
						x = 4;
					else if(s[k] == 'n')
						x = 5;
					break;

				}
		
			break;
		}
		cnt = 0;
		for(int j = 0;j + i < len;j++)
			if(s[i + j] == funcs[j])
				cnt++;
			else
				break;
		if(cnt == 5)
		{
			y = 4;
			for(int j = i + 6;j  + 1 < len;j++)
			{
				if(s[j] == 'm' && s[j + 1] == 't')
					y += 1;
				else if(s[j] == 'm' && s[j + 1] == 'i')
					y += 3;
				else if(s[j] == 'a' && s[j + 1] == 'a')
					y += 2;
				else if(s[j] == 'a' && s[j + 1] == 'r')
					y += 0;
				break;
			}
			for(int j = i + 6;j + 1 < len;j++)
				if(s[j] == '/')
				{
					int k = j + 1;
					if(s[k] == 'o')
						x = 0;
					else if(s[k] == 'g')
						x = 1;
					else if(s[k] == 'a')
						x = 2;
					else if(s[k] == 'r')
						x = 3;
					else if(s[k] == 'i')
						x = 4;
					else if(s[k] == 'n')
						x = 5;
					break;
				}
		
			break;
		}
	}
	return y * 6 + x;
}
int main(int argc, char* argv[])
{
	char s[100];
	double res[80][10];
	for(int i = 0;i < 72;i++)
		for(int j = 0;j < 8;j++)
			res[i][j] = 23;
	for(int n = 1; n < argc;n++)
	{

		//printf("------%s------\n",argv[n]);

		freopen(argv[n],"r",stdin);
		int id = check_arch(argv[n]);
		scanf("%s",s);
		for(int i = 0;i < 8;i++)
		{
			scanf("%s",s);
			if(s[0] == '0')
				res[id][i] = 0;
			else if(s[0] == '1')
				res[id][i] = 100;
			else
			{
				int len = strlen(s);
				res[id][i] = 0.0;
				for(int j = 1;j < len;j++)
					res[id][i] = res[id][i] * 10 + (s[j] - '0');
				res[id][i] /= 100.0;
			}
		}
		// printf("\t%.2f\t%.2f\n",res[id][0],res[id][1]);
		// printf("\t%.2f\t%.2f\n",res[id][2],res[id][3]);
		// printf("\t%.2f\t%.2f\n",res[id][4],res[id][5]);
		// printf("\t%.2f\t%.2f\n",res[id][6],res[id][7]);
		// printf("\n---------%.2f\t%.2f\n\n",(res[0] + res[2] + res[4] + res[6]) / 4,(res[1] + res[3] + res[5] + res[7]) / 4);
	}
	// printf("\t\tObjdump\tGhidra\tAngr\tRadare2\tIDA\tNinja\n");
	printf("   -----Objdump-----  ------Ghidra-----  ------Angr-------  -----Radare2-----  ------IDA--------  ------Ninja------\n");
	// printf("")
	for(int i = 0;i < 12;i++)
	{
		if(i == 0)
			printf("\n   -------------------------------------------------Instructions-----------------------------------------------------\n\n");
		if(i % 4 == 0)
			printf("   -----------------------------------------------------Arm32-------------------------------------------------------\n");
		if(i % 4 == 1)
			printf("   -----------------------------------------------------Thumb-------------------------------------------------------\n");
		if(i % 4 == 2)
			printf("   -----------------------------------------------------AArch64-----------------------------------------------------\n");
		if(i % 4 == 3)
			printf("   ------------------------------------------------------Mips-------------------------------------------------------\n");

		for(int j = 0;j < 4;j++)
		{
			if(j == 0)
				printf("O2 ");
			if(j == 1)
				printf("O3 ");
			if(j == 2)
				printf("OS ");
			if(j == 3)
				printf("Of ");
			for(int k = 0;k < 6;k++)
				if(res[i * 6 + k][j * 2] == 23.00)
					printf("   ------  ------ |");
				else
					printf("   %6.2f  %6.2f |",res[i * 6 + k][j * 2],res[i * 6 + k][j * 2 + 1]);
			printf("\n");
		}
		if(i == 3)
			printf("\n   ---------------------------------------------------Functions-----------------------------------------------------\n\n");
		else if(i == 7)
			printf("\n   -------------------------------------------------Jump Tables------------------------------------------------------\n\n");
		// else
		// 	printf("   -----------------------------------------------------------------------------------------------------------------\n");

	}
}
