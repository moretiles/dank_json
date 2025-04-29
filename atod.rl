/*
 * Convert a string to an integer.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <math.h>

size_t num(const char *str, long long *val){
        size_t len = 0;
        *val = 0;
        if(str){
                while(*str <= '9' && '0' <= *str){
                        len++;
                        *val = *val * 10 + (*str - '0');
                        str++;
                }
        }
        return len;
}

double as_decimal(long long val){
	if(val == 0){
		return 0;
	}
	int N = 0;
	N = 1 + log(val) / log(10);
	return (double) val / (double) pow(10, N);
}

%%{
	machine atod_json;
	write data;
}%%

double atod_json( char *str )
{
	char *p = str, *pe = str + strlen( str );
	int cs;
	long long whole = 0, decimal = 0, exponent = 0;
	double sum = 0;
	bool neg = false, dec = false, exp = false, exp_neg = false;

	%%{
		action process_whole      { num(p, &whole); }
		action process_decimal    { num(p, &decimal); }
		action process_exponent   { num(p, &exponent); }
		action neg                { neg = true; }
		action dec                { dec = true; }
		action exp                { exp = true; }
		action exp_neg            { exp_neg = true; }
		action number             { /*NUMBER*/ }

		number = (
				( '+' | '-' $neg )? digit+ >process_whole 
				( '.' $dec digit+ >process_decimal )?
				( [eE] ( '+' | '-' $exp_neg )? digit+ >process_exponent )?
			 ) %number;

		main := ( number '\n' )*;

		# Initialize and execute.
		write init;
		write exec;
	}%%

	sum = whole;

	sum += as_decimal(decimal);

	if ( exp_neg )
		exponent = -1 * exponent;

	sum *= pow(10, exponent);

	if ( neg )
		sum = -1 * sum;

	if ( cs < atod_json_first_final )
		fprintf( stderr, "atod_json: there was an error\n" );

	return sum;
};


#define BUFSIZE 1024

int main()
{
	char buf[BUFSIZE];
	while ( fgets( buf, sizeof(buf), stdin ) != 0 ) {
		double value = atod_json( buf );
		printf( "%f\n", value );
	}
	return 0;
}
