#include <stdio.h>
#include <stdlib.h>

int* idb(long long int x);
int* kb(long long int x);
int* nb(long long int x);
int* Arb(long long int x);
int* Atb(long long int x);
int keystream(int a[48]);
int* shifting(int a[48],int b, int c);
int* LFSR(int a[48]);

int main()
{
    long long int I, K, Answer=4294967295, Password;
    int i, j, l;
    int a[48],b[2500],EnNonce[32],EnAr[32],EnAt[32];
//Identifier id
    printf("Enter Identifier id: ");
    scanf("%lld",&I);
    int* id = idb(I);
//Secret Key
    printf("\nEnter Secret Key k: ");
    scanf("%lld",&K);
    int* k = kb(K);
//Random Nonce
    srand(time(0));
    long long int r = rand()%4294967295+1 ;
    printf("\nrandom number is:%lld\n",r);
    int* n = nb(r);
//Answer
    int* Ar = Arb(Answer);
//Password
    printf("\nEnter Password: ");
    scanf("%lld",&Password);
    int* At = Atb(Password);
//Printing Identifier, Secret Key, Nonce, Answer & Password
    printf("\n\nIdentifier id is ");
    for (i=0; i<32; i++)
        printf("%d",id[i]);
    printf("\nSecret Key is ");
    for (i=0; i<48; i++)
        printf("%d",k[i]);
    printf("\nRandom Nonce is ");
    for (i=0; i<32; i++)
        printf("%d",n[i]);
    printf("\nAnswer is ");
    for (i=0; i<32; i++)
        printf("%d",Ar[i]);
    printf("\nPassword is ");
    for (i=0; i<32; i++)
        printf("%d",At[i]);
//Loading LFSR stage -> a0 to a47
    for (i=0; i<32; i++)
        a[i] = id[i];
    i=32; j=0;
    while (i!=48)
    {
        a[i] = k[j];
        i++;
        j++;
    }
    printf("\n\nLoaded Register a0 to a47 is ");
    for (i=0; i<32; i++)
        printf("%d",a[i]);
    printf(" ");
    for (i=32; i<48; i++)
        printf("%d",a[i]);
//Keystream 1st bit - b0
    b[0] = keystream(a);
    printf("\n\n\nb0 is  %d",b[0]);
//Keystream b1 to b31 and Register till a48 to a79
    j=16; l=0;
    for (i=1; i<32; i++)
    {
        a[48] = shifting(a,k[j],n[l]);
        b[i] = keystream(a);
        j++; l++;
    }
    printf("\n\nLFSR initial state(a32 to a79 is ");
    for (i=0; i<47; i++)
        printf("%d",a[i]);
//Keystream from b32 and Register from a80
    for (i=32; i<300; i++)
    {
        a[48] = LFSR(a);
        b[i] = keystream(a);
    }
//Encrypted Nonce
    for (i=0; i<32; i++)
        EnNonce[i] = n[i] ^ b[i];
    printf("\n\nEncrypted Nonce is ");
    for (i=0; i<32; i++)
        printf("%d",EnNonce[i]);
//Encrypted Answer
    for (i=0; i<32; i++)
        EnAr[i] = Ar[i] ^ b[32+i];
    printf("\n\nEncrypted Answer is ");
    for (i=0; i<32; i++)
        printf("%d",EnAr[i]);
//Encrypted Password
    for (i=0; i<32; i++)
        EnAt[i] = At[i] ^ b[64+i];
    printf("\n\nEncrypted Password is ");
    for (i=0; i<32; i++)
        printf("%d",EnAt[i]);
    printf("\n\n\n\n\n\n");

    return 0;
}

////Functions

//identifier - decimal to binary
int* idb(long long int x)
{
    static int y[32];
    for (int i=0; i<32; i++)
        y[i] = 0;
    for (int i=31; x>0; i--)
    {
        y[i] = x%2 ;
        x = x/2 ;
    }
    return y;
}

//key - decimal to binary
int* kb(long long int x)
{
    static int y[48];
    for (int i=0; i<48; i++)
        y[i] = 0;
    for (int i=47; x>0; i--)
    {
        y[i] = x%2 ;
        x = x/2 ;
    }
    return y;
}

//nonce - decimal to binary
int* nb(long long int x)
{
    static int y[32];
    for (int i=0; i<32; i++)
        y[i] = 0;
    for (int i=31; x>0; i--)
    {
        y[i] = x%2 ;
        x = x/2 ;
    }
    return y;
}

//Answer - decimal to binary
int* Arb(long long int x)
{
    static int y[32];
    for (int i=0; i<32; i++)
        y[i] = 0;
    for (int i=31; x>0; i--)
    {
        y[i] = x%2 ;
        x = x/2 ;
    }
    return y;
}

//Password - decimal to binary
int* Atb(long long int x)
{
    static int y[32];
    for (int i=0; i<32; i++)
        y[i] = 0;
    for (int i=31; x>0; i--)
    {
        y[i] = x%2 ;
        x = x/2 ;
    }
    return y;
}
//Keystream - Filter Functions
int keystream(int a[48])
{
    int f1, f2, f3, f4, f5, f;
    f1 = (((a[2]|a[3])&a[5])^(a[2]|a[6])^a[3]);
    f2 = (((a[15]|a[14])&(a[8]^a[12]))^(a[15]|a[8]|a[12]));
    f3 = (((a[26]|a[23])&(a[17]^a[21]))^(a[26]|a[17]|a[21]));
    f4 = (((a[33]|a[31])&(a[28]^a[29]))^(a[33]|a[28]|a[29]));
    f5 = (((a[34]|a[43])&a[44])^(a[34]|a[46])^a[43]);
    f = ((((((f3^f5)|f4)&f1)^f2)&(f3^f2))^(((f4^f5)|f1)|((f4^f2)|f3)));
    return f;
}

//Shift operation till a[80]
int* shifting(int a[48],int b, int c)
{
    int i,j,k,t,x,y,z;
    y = b; z = c;
    for (i=0; i<48; i++)
    {
        t = a[i];
        j=0; k=1;
        while(j!=47)
        {
            a[j] = a[k];
            j++; k++;
        }
    }
    x = keystream(a);
    a[47] = x^y^z;
    return a;
}

//keystream and LFSR from a[80]
int* LFSR(int a[48])
{
    int i,j,k,t;
    for (i=0; i<48; i++)
    {
        t = a[i];
        j=0; k=1;
        while(j!=47)
        {
            a[j] = a[k];
            j++; k++;
        }
    }
    a[48] = a[0]^a[2]^a[3]^a[6]^a[7]^a[8]^a[16]^a[22]^a[23]^a[26]^a[30]^a[41]^a[42]^a[43]^a[46]^a[47];
    return a;
}
