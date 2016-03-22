/*

	This file is part of the Malbolge disassembler.
	Copyright (C) 2016 Matthias Ernst

	The Malbolge disassembler is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation, either version 3 of
	the License, or (at your option) any later version.

	The Malbolge disassembler is distributed in the hope that it will be
	useful, but WITHOUT ANY WARRANTY; without even the implied warranty
	of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program. If not, see <http://www.gnu.org/licenses/>.

	E-Mail: info@matthias-ernst.eu



	For more Malbolge stuff, please visit
	<http://www.matthias-ernst.eu/malbolge.html>

*/

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "main.h"

volatile sig_atomic_t sigint_store = 0;
const char* translation = "5z]&gqtyfr$(we4{WP)H-Zn,[%\\3dL+Q;>U!pJS72FhOA1CB6v^=I_0/8|jsb9m<.TVac`uY*MK'X~xDl}REokN:#?G\"i@";
int main(int argc, char* argv[]);
int parse_input_args(int argc, char** argv, char** output_filename, char*** user_input_files,
		char** debug_filename, const char** input_filename);
void print_usage_message(char* executable_name);
unsigned int crazy(unsigned int a, unsigned int d);
unsigned int rotate_r(unsigned int d);
int load_malbolge_program(struct VMState* initial_state, const char* malbolge_file);
int find_entrypoint(struct VMState* entry_state, int* steps_to_entrypoint, const struct VMState* initial_state);
int interactive_access_analysis(struct AccessAnalysis* accesses, const struct VMState* entry_state);
int optimize_entrypoint(struct VMState* entry_state, int* steps_to_entrypoint, struct AccessAnalysis* accesses, const struct VMState* initial_state);
int extract_codeblocks(struct ConnectedMemoryCells** creg_components, struct ConnectedMemoryCells** dreg_components,
		struct AccessAnalysis* accesses, const struct VMState* entry_state);
void add_dreg_normal_successor(struct AccessAnalysis* accesses, int cell, int successor);
void add_dreg_normal_predecessors(struct AccessAnalysis* accesses, int cell, int successor);
void add_jmp_destination(struct AccessAnalysis* accesses, int cell, int destination);
void add_movd_destination(struct AccessAnalysis* accesses, int cell, int destination);
void sigint_handler(int s);
void fprint_instruction(FILE* out_stream, int value, int position);
void fprint_xlat_cycle(FILE* out_stream, int value, int position);

int compare_integer (const void* avl_a, const void* avl_b, void* avl_param) {
	if (*((int*)avl_a) > *((int*)avl_b))
		return 1;
	else if (*((int*)avl_a) < *((int*)avl_b))
		return -1;
	else
		return 0;
}



int main(int argc, char* argv[]) {

	const char* malbolge_file = 0;
	char* output_filename = 0;
	char** user_input_files = 0;
	char* debug_filename = 0;
	struct VMState initial_state;
	struct VMState entry_state;
	int steps_to_entrypoint = 0;
	struct AccessAnalysis accesses;
	struct ConnectedMemoryCells* creg_components = 0;
	struct ConnectedMemoryCells* dreg_components = 0;
	int result;


	printf("This is the Malbolge disassembler v0.1 by Matthias Ernst.\n");
	if (!parse_input_args(argc, argv,&output_filename,&user_input_files,&debug_filename,&malbolge_file)){
		print_usage_message(argc>0?argv[0]:0);
		return 0;
	}

	result = load_malbolge_program(&initial_state, malbolge_file);
	if (result != 0) {
		return result;
	}
	result = find_entrypoint(&entry_state, &steps_to_entrypoint, &initial_state);
	if (result != 0) {
		return result;
	}
	result = interactive_access_analysis(&accesses, &entry_state);
	if (result != 0) {
		return result;
	}
	result = optimize_entrypoint(&entry_state, &steps_to_entrypoint, &accesses, &initial_state);
	if (result != 0) {
		return result;
	}

	result = extract_codeblocks(&creg_components, &dreg_components, &accesses, &entry_state);
	if (result != 0) {
		return result;
	}


	// TODO: find label-positions and preceeding RNops... (maybe not so important)



	printf("Malbolge disassembler has finished its analysis of the Malbolge program.\n");
	printf("Malbolge disassembler will generate the HeLL file now. Please wait...");
	// TODO: generate HeLL-code from creg_components, dreg_components, and initial A-value:
	// TODO: output blocks; regard fixed offsets, entry state: ENTRY as well as initial A register value
	
	FILE* output_file = fopen(output_filename, "w");
	if (!output_file) {
		fprintf(stderr,"Cannot write to file: %s",output_filename);
	}
	struct ConnectedMemoryCells* current_creg_component = creg_components;
	fprintf(output_file,".CODE\n");
	if (accesses.a_register_matters) {
		fprintf(output_file,"INIT_A:\n\tRot\n\tMovD\n\tJmp\n\n");
	}
		
	while (current_creg_component->cells) {
		int last_executed_address = -2;
		struct avl_traverser it;
		// the ordered AVL tree may break our codeblock / datablock on overflow (59048 -> 0)
		// this is fixed by the following workaround:
		// the extract_codeblocks methods detects these cases and sets the offset to be fixed.
		// however, this only works for .DATA section.
		// in .CODE section we get problems with overlapping OFFSETs, because preceeding cell is always reserved.
		// therefore, try to detect this case!
		int tmp_val = 0;
		int* tmp = (int*)avl_find(current_creg_component->cells, &tmp_val);
		if (tmp) {
			tmp_val = 59048;
			tmp = (int*)avl_find(current_creg_component->cells, &tmp_val);
			if (tmp) {
				// we have the problem described above
				// now we have to find smallest precessor we culd start iteration with...
				while (tmp && tmp_val > 0) {
					tmp_val--;
					tmp = (int*)avl_find(current_creg_component->cells, &tmp_val);
				}
				// tmp_val is starting index!
			} else {
				tmp_val = 0;
			}
		}
		int start_index = tmp_val;
		int* c_pos;
		avl_t_init(&it, current_creg_component->cells);
		int ln_break_offset = 0;
		while (1) {
			if (tmp_val) {
				tmp_val++;
				if (tmp_val > 59048) {
					tmp_val = 0;
				}
			}
			if (tmp_val) {
				c_pos = &tmp_val;
			}else{
				c_pos = (int*)avl_t_next(&it);
				if (!c_pos) {
					break;
				}
				if (start_index && *c_pos > start_index) {
					break;
				}
			}
			int set_label = 0;
			int output_command = 0;
			if (accesses.memory[*c_pos].access & CREG_EXECUTED) {
				output_command = 1;
				if ((last_executed_address + 1)%59049 != *c_pos) {
					// set label, set offset if necessary
					set_label = 1;
					if (current_creg_component->fixed_offset) {
						// set offset
						if (ln_break_offset) {
							fprintf(output_file,"\n");
						}
						fprintf(output_file,".OFFSET %d\n", *c_pos);
					}
				}
				last_executed_address = *c_pos;
			}
			if (accesses.memory[*c_pos].access & CREG_REACHED_BY_JMP) {
				// set label
				set_label = 1;
			}
			if (set_label) {
				fprintf(output_file,"CODE_%d:\n", *c_pos);
			}
			if (output_command) {
				fprintf(output_file,"\t");
				// command 2 cycle
				if (accesses.memory[*c_pos].access & CREG_TRANSLATED) {
					fprint_xlat_cycle(output_file, entry_state.memory[*c_pos], *c_pos);
				}else{
					fprint_instruction(output_file, entry_state.memory[*c_pos], *c_pos);
				}
				fprintf(output_file,"\n");
			}
			ln_break_offset = 1;
		}
		fprintf(output_file, "\n");
		current_creg_component++;
	}
	struct ConnectedMemoryCells* current_dreg_component = dreg_components;
	fprintf(output_file,".DATA\n");
	if (accesses.a_register_matters) {
		fprintf(output_file,"ENTRY:\n\tINIT_A %d<<1\n\tORIGINAL_ENTRY\n\n", entry_state.a);
	}
	while (current_dreg_component->cells) {
	
		int last_output_address = -1;
		struct avl_traverser it;
		// the ordered AVL tree may break our codeblock / datablock on overflow (59048 -> 0)
		// this is partially fixed by the following workaround:
		// the extract_codeblocks methods detects these cases and sets the offset to be fixed.
		avl_t_init(&it, current_dreg_component->cells);
		int* d_pos;
		while ((d_pos = (int*)avl_t_next(&it))) {
			int set_label = 0;
			int set_code_label = 0;
			int print_offset = 0;
			if (last_output_address < 0) {
				set_label = 1;
			}
			if (current_dreg_component->fixed_offset && last_output_address < 0) {
				print_offset = 1;
			}
			if (last_output_address >= 0 && last_output_address + 1 < *d_pos && !print_offset) {
				// print out unused memory cells (to match offsets).
				int i;
				for (i=last_output_address+1;i<*d_pos;i++) {
					fprintf(output_file,"\t?-\n");
				}
			}
			if (accesses.memory[*d_pos].access & DREG_REACHED_BY_MOVD) {
				set_label = 1;
			}
			if (accesses.memory[*d_pos].access & CREG_REACHED_BY_JMP) {
				set_code_label = 1;
			}
			
			
			if (print_offset) {
				if (last_output_address >= 0){
					fprintf(output_file,"\n");
				}
				fprintf(output_file,".OFFSET %d\n", *d_pos);
			}
			// if at entry position:
			if (*d_pos == entry_state.d) {
				if (accesses.a_register_matters) {
					fprintf(output_file,"ORIGINAL_ENTRY:\n");
				}else{
					fprintf(output_file,"ENTRY:\n");
				}
			}
			if (set_code_label) {
				fprintf(output_file,"CODE_%d:\n", *d_pos);
			}
			if (set_label) {
				fprintf(output_file,"DATA_%d:\n", *d_pos);
			}

			fprintf(output_file,"\t");
			// print data word: LABEL or CONSTANT
			if (accesses.memory[*d_pos].access & DREG_ACCESS_RW) {
				// CONSTANT
				if (entry_state.memory[*d_pos] == 0) {
					fprintf(output_file,"C0");
				}else if (entry_state.memory[*d_pos] == 59048/2) {
					fprintf(output_file,"C1");
				}else if (entry_state.memory[*d_pos] == 59048-2) {
					fprintf(output_file,"C20");
				}else if (entry_state.memory[*d_pos] == 59048-1) {
					fprintf(output_file,"C21");
				}else if (entry_state.memory[*d_pos] == 59048) {
					fprintf(output_file,"C2");
				}else if (entry_state.memory[*d_pos] == '\n') {
					fprintf(output_file,"'\\n'");
				}else if (entry_state.memory[*d_pos] >= 32 && entry_state.memory[*d_pos] <= 126) {
					fprintf(output_file,"'%c'",(char)entry_state.memory[*d_pos]);
				}else{
					// TODO: as trinary number
					fprintf(output_file,"%d",entry_state.memory[*d_pos]);
				}
			}else if (accesses.memory[*d_pos].access & DREG_ACCESS_JUMP) {
				// CODE LABEL
				fprintf(output_file,"CODE_%d",entry_state.memory[*d_pos]+1);
			}else if (accesses.memory[*d_pos].access & DREG_ACCESS_MOVD) {
				// DATA LABEL
				fprintf(output_file,"DATA_%d",entry_state.memory[*d_pos]+1);
			}else if (accesses.memory[*d_pos].access & DREG_REACHED_BY_MOVD){
				// value does not matter, but cell must have a label, therefore must be "?" instead of "?-"
				fprintf(output_file,"?");
			}else{
				// MUST NOT OCCUR
				fprintf(output_file,"INVALID");
			}
			fprintf(output_file, "\n");
			last_output_address = *d_pos;
			
		}
		fprintf(output_file, "\n");
		current_dreg_component++;
	}
	
	// TODO: initial A value
	
	fclose(output_file);
	fflush(stdout);

	printf(" done.\n");


	free_access_analysis(&accesses);
	return 0;
}

void fprint_instruction(FILE* out_stream, int value, int position) {
	int instruction = (value+position)%94;
	switch (instruction){
		case 4:
			fprintf(out_stream, "Jmp");
			return;
		case 5:
			fprintf(out_stream, "Out");
			return;
		case 23:
			fprintf(out_stream, "In");
			return;
		case 39:
			fprintf(out_stream, "Rot");
			return;
		case 40:
			fprintf(out_stream, "MovD");
			return;
		case 62:
			fprintf(out_stream, "Opr");
			return;
		case 81:
			fprintf(out_stream, "Hlt");
			return;
		case 68:
		default:
			fprintf(out_stream, "Nop");
			return;
	}
}

int is_nop(int value, int position) {
	int instruction = (value+position)%94;
	switch (instruction){
		case 4:
		case 5:
		case 23:
		case 39:
		case 40:
		case 62:
		case 81:
			return 0;
		case 68:
		default:
			return 1;
	}
}

void fprint_xlat_cycle(FILE* out_stream, int value, int position) {

	if (value < 33 || value > 126) {
		fprintf(out_stream,"Invalid");
		return;
	}
	value -= 33;
	
	int tmp = value;
	int cycle_len = 0;
	int pure_nop_cycle = 1;
	do {
		if (!is_nop(tmp+33,position)) {
			pure_nop_cycle = 0;
		}
		tmp = translation[tmp] - 33;
		cycle_len++;
	}while(tmp != value);
	if (pure_nop_cycle) {
		fprintf(out_stream, "RNop");
		return;
	}
	if (cycle_len > 9) {
		// probabliy use-once-code
		fprint_instruction(out_stream, value+33, position);
		return;
	}
	// print complete cycle
	cycle_len = 0;
	do {
		if (cycle_len) {
			fprintf(out_stream,"/");
		}
		fprint_instruction(out_stream, tmp+33, position);
		tmp = translation[tmp] - 33;
		cycle_len++;
	}while(tmp != value);
}


int parse_input_args(int argc, char** argv, char** output_filename, char*** user_input_files,
		char** debug_filename, const char** input_filename) {
	int i;
	int debug_mode = 0;
	if (argc<2 || argv == 0 || output_filename == 0 || user_input_files == 0 || debug_filename == 0 || input_filename == 0) {
		return 0;
	}
	*output_filename = 0;
	*input_filename = 0;
	*user_input_files = 0;
	*debug_filename = 0;
	for (i=1;i<argc;i++) {
		if (argv[i][0] == '-') {
			/* read parameter */
			switch (argv[i][1]) {
				// long int tmp;
				case 'o':
					i++;
					if (*output_filename != 0) {
						return 0; /* double parameter: -o */
					}
					if (i>=argc) {
						return 0; /* missing argument for parameter: -l */
					}
					*output_filename = (char*)malloc(strlen(argv[i])+1);
					memcpy(*output_filename,argv[i],strlen(argv[i])+1);
					break;
/*				case 'i':
					i++;
					if (i>=argc) {
						return 0; / * missing argument for parameter: -l * /
					}
					// TODO: implement
					break;
				case 'd':
					if (debug_mode != 0) {
						return 0; / * double parameter: -l * /
					}
					debug_mode = 1;
					break;
*/
				default:
					return 0; /* unknown parameter */
			}
		}else{
			/* read input file name */
			if (*input_filename != 0) {
				return 0; /* more than one input file given */
			}
			*input_filename = argv[i];
		}
	}
	if (*input_filename == 0) {
		return 0; /* no input file name given */
	}
	if (*output_filename == 0) {
		char* file_extension;
		size_t input_file_name_length;
		/* get file extension and overwrite it - or append it. */
		file_extension = strrchr((char*)*input_filename,'.');
		if (file_extension == 0 || strrchr(*input_filename,'\\')>file_extension || strrchr(*input_filename,'/')>file_extension) {
			input_file_name_length = strlen(*input_filename);
		}else{
			if (strcmp(file_extension+1,HELL_FILE_EXTENSION)==0) {
				input_file_name_length = strlen(*input_filename);
			}else{
				input_file_name_length = file_extension - *input_filename;
			}
		}
		/* add extension HELL_FILE_EXTENSION to file name. */
		*output_filename = (char*)malloc(input_file_name_length+1+strlen(HELL_FILE_EXTENSION)+1);
		memcpy(*output_filename,*input_filename,input_file_name_length);
		(*output_filename)[input_file_name_length] = '.';
		memcpy(*output_filename+input_file_name_length+1,HELL_FILE_EXTENSION,strlen(HELL_FILE_EXTENSION)+1);
	}
	if (debug_mode) {
		char* file_extension;
		size_t output_file_name_length;
		/* get file extension and overwrite it - or append it. */
		file_extension = strrchr(*output_filename,'.');
		if (file_extension == 0 || strrchr(*output_filename,'\\')>file_extension || strrchr(*output_filename,'/')>file_extension) {
			output_file_name_length = strlen(*output_filename);
		}else{
			if (strcmp(file_extension+1,MALBOLGE_DEBUG_FILE_EXTENSION)==0) {
				output_file_name_length = strlen(*output_filename);
			}else{
				output_file_name_length = file_extension - *output_filename;
			}
		}
		/* add extension MALBOLGE_DEBUG_FILE_EXTENSION to file name. */
		*debug_filename = (char*)malloc(output_file_name_length+1+strlen(MALBOLGE_DEBUG_FILE_EXTENSION)+1);
		memcpy(*debug_filename,*output_filename,output_file_name_length);
		(*debug_filename)[output_file_name_length] = '.';
		memcpy(*debug_filename+output_file_name_length+1,MALBOLGE_DEBUG_FILE_EXTENSION,strlen(MALBOLGE_DEBUG_FILE_EXTENSION)+1);
	}
	return 1; /* success */
}

void print_usage_message(char* executable_name) {
	printf("Usage: %s [options] <input file name>\n",executable_name!=0?executable_name:"./md");
	printf("Options:\n");
	printf("  -o <file>        Write output to <file>\n");
//	printf("  -i <inputfile>   Input file for non-interactive flow analysis\n");
//	printf("                   You may repeat this parameter to list several input files\n");
//	printf("  -d               Write debugging information\n");
}



unsigned int crazy(unsigned int a, unsigned int d){
	unsigned int crz[] = {1,0,0,1,0,2,2,2,1};
	int position = 0;
	unsigned int output = 0;
	while (position < 10){
		unsigned int i = a%3;
		unsigned int j = d%3;
		unsigned int out = crz[i+3*j];
		unsigned int multiple = 1;
		int k;
		for (k=0;k<position;k++)
			multiple *= 3;
		output += multiple*out;
		a /= 3;
		d /= 3;
		position++;
	}
	return output;
}

unsigned int rotate_r(unsigned int d){
	unsigned int carry = d%3;
	d /= 3;
	d += 19683 * carry;
	return d;
}


int load_malbolge_program(struct VMState* initial_state, const char* malbolge_file) {
	if (!initial_state || !malbolge_file) {
		return 1;
	}

	printf("Loading Malbolge program...");
	fflush(stdout);
	unsigned int result;
	FILE* file;

	file = fopen(malbolge_file,"rb");
	if (file == NULL) {
		printf("\n");
		fprintf(stderr, "File not found: %s\n",malbolge_file);
		return 1;
	}
	initial_state->a=0;
	initial_state->c=0;
	initial_state->d=0;
	result = 0;
	while (!feof(file) && initial_state->d < 59050){
		unsigned int instr;
		initial_state->memory[initial_state->d] = 0;
		result = fread(initial_state->memory+initial_state->d,1,1,file);
		if (result > 1) {
			return 1;
		}
		if (result == 0 || initial_state->memory[initial_state->d] == 0x1a || initial_state->memory[initial_state->d] == 0x04) {
			break;
		}
		instr = (initial_state->memory[initial_state->d] + initial_state->d)%94;
		if (initial_state->memory[initial_state->d]==' ' || initial_state->memory[initial_state->d] == '\t' || initial_state->memory[initial_state->d] == '\r' || initial_state->memory[initial_state->d] == '\n') {
			continue;
		}else if (initial_state->memory[initial_state->d] >= 33 && initial_state->memory[initial_state->d] < 127 &&
				(instr == 4 || instr == 5 || instr == 23 || instr == 39 ||
						instr == 40 || instr == 62 || instr == 68 || instr == 81)) {
			initial_state->d++;
		}else{
			printf("\n");
			fprintf(stderr, "Invalid character 0x%02x at 0x%05x.\n",(char)(initial_state->memory[initial_state->d]),initial_state->d);
			return 1; //invalid characters are not accepted.
			//that makes the "hacked" in-out-program unrunnable
			// TODO: give warning message and allow it here - this is a debugger, not an interpreter
		}
	}
	if (file != stdin) {
		fclose(file);
	}
	if (initial_state->d == 59050) {
		printf("\n");
		fprintf(stderr, "Maximum program length of 59049 exceeded.\n");
		return 1;
	}
	if (initial_state->d < 2) {
		printf("\n");
		fprintf(stderr, "Minimal program length of 2 deceeded.\n");
		return 1;
	}

	while (initial_state->d < 59049){
		initial_state->memory[initial_state->d] = crazy(initial_state->memory[initial_state->d-1], initial_state->memory[initial_state->d-2]);
		initial_state->d++;
	}
	initial_state->d = 0;

	printf(" done.\n");
	return 0;
}



int find_entrypoint(struct VMState* entry_state, int* steps_to_entrypoint, const struct VMState* initial_state) {
	struct VMState tmp_state;
	if (!initial_state) {
		return 1;
	}
	printf("\nMalbolge disassembler tries to find the entry point...");
	fflush(stdout);
	copy_state(&tmp_state,initial_state);

	struct BreakCondition break_on = {0, 0, MALBOLGE_IN | MALBOLGE_OUT};
	int steps = 0;
	// TODO: prevent from infinite loop; maybe set a maximum number of steps and ask what to do whenever the maximum number is reached
	execute(&tmp_state, 0, 0, break_on, &steps, 0, 0, 0);
	// execute until entry point (which is last JMP before first IN/OUT/HLT command)
	copy_state(&tmp_state,initial_state);
	break_on.maximal_steps = steps;
	break_on.on_cseg_outside_analysis = 0;
	break_on.command_mask = 0;
	if (steps > 0) {
		execute(&tmp_state, 0, 0, break_on, 0, 0, 0, 0);
	}
	if (!(tmp_state.memory[tmp_state.c] >= 33 && tmp_state.memory[tmp_state.c] <= 126 && (tmp_state.memory[tmp_state.c]+tmp_state.c)%94 == 4)) {
		// no JMP command at entry point position
		printf("\n");
		fprintf(stderr,"Failed to find the entry point.\n");
		return 1; // failed to find entry point
	}
	if (steps_to_entrypoint) {
		*steps_to_entrypoint = steps;
	}
	if (entry_state) {
		copy_state(entry_state,&tmp_state);
	}
	printf(" done.\nEntry point found at step %d.\n",*steps_to_entrypoint);
	return 0;
}



int interactive_access_analysis(struct AccessAnalysis* accesses, const struct VMState* entry_state) {
	if (!entry_state || !accesses) {
		return 1;
	}
	// ask user for help to generate different runs of the Malbolge program
	printf("\nThe disassembler needs to identify the memory cells that are ever used.\n");
	printf("Therefore the disassembler will execute the Malbolge program now.\n");
	printf("Please interact with the Malbolge program if it asks for input.\n");
	printf("You can interrupt execution of the Malbolge program and continue disassembling\nby pressing CTRL+C anytime.\n");
	printf("Note that it is mandatory for disassembling that every branch of the Malbolge\nprogram will be entered.\n");
	printf("Because of that, Malbolge disassembler allows you to run the Malbolge program\nmultiple times with different input each.\n\n");
	printf("Press return to start the Malbolge program execution.\n");
	fflush(stdout);
	do {
		int in = getchar();
		if (in == EOF) {
			printf("\n");
			return 1; // user canceled
		}
		if ((char)in == '\n') {
			break; // return pressed
		}
	}while(1);

	struct sigaction sigIntHandler, oldSigIntHandler;
	sigIntHandler.sa_handler = sigint_handler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;
	sigaction(SIGINT, &sigIntHandler, &oldSigIntHandler);
	int action = 0;
	memset(accesses, 0, sizeof(struct AccessAnalysis));
	do {
		int interrupted = 0;
		printf("Running Malbolge program...\n");
		struct VMState tmp_state;
		copy_state(&tmp_state,entry_state);
		struct BreakCondition break_on = {0, 0, 0};
		struct UserInput input = {0, 0};
		int steps = execute(&tmp_state, 1, &input, break_on, 0, &interrupted, accesses, 0);
		if (steps > accesses->maximal_steps_from_entry_point) {
			accesses->maximal_steps_from_entry_point = steps;
		}
		printf("\nMalbolge program %s %d steps behind entry point.\n",interrupted?"interrupted":"terminated",steps);
		if (input.length == 0 && !interrupted) {
			// no interaction
			if (input.input != 0) {
				free(input.input);
				input.input = 0;
			}
			printf("Malbolge program terminated without user interaction. No further run is\nnecessary.\n");
			break;
		}
		// input saving/reusing is not implemented yet, so we can delete it here.
		if (input.input != 0) {
			free(input.input);
			input.input = 0;
			input.length = 0;
		}
		printf("Do you want to execute the Malbolge program again? [Y/n] ");
		fflush(stdout);
		action = -1;
		do {
			int in = getchar();
			if (in == EOF) {
				printf("\n");
				return 1; // user canceled
			}
			if ((char)in == '\n') {
				if (action == -1)
					action = 1;
				break; // return pressed
			}
			if (action == -1 && ((char)in == 'n' || (char)in == 'N')) {
				action = 0;
			} else {
				action = 1;
			}
		}while(1);
	}while(action);
	sigaction(SIGINT, &oldSigIntHandler, 0);
	return 0;
}


int optimize_entrypoint(struct VMState* entry_state, int* steps_to_entrypoint, struct AccessAnalysis* accesses, const struct VMState* initial_state) {
	if (!entry_state || !steps_to_entrypoint || !accesses || !initial_state) {
		return 1;
	}

	// test whether jmp command of entry point lies inside the Malbolge program (accessed as CREG_EXECUTED later)
	if (accesses->memory[entry_state->c].access & CREG_EXECUTED) {
		struct BreakCondition break_on;
		printf("\nNow Malbolge disassembler tries to find a better entry point.\n");
		printf("This may take some time. Please wait...");
		fflush(stdout);
		// optimize entry point

		// optimized entry point: start with zero.
		// Malbolge program: start fresh from file, run at most as many steps as needed to reach the known entry-point
		// whenever a CSEG-command outside the AccessAnalysis (make a tmp copy!) is executed, set the new optimized entry point at the next JMP behind this value
		// (or AT this value if it is a JMP instruction)
		int optimized_entry_steps = 0;
		struct VMState optimized_entry_state;
		struct AccessAnalysis tmp_accesses;
		copy_state(&optimized_entry_state,initial_state);
		copy_access_analysis(&tmp_accesses, accesses);

		int steps = 0;

		do {
			break_on.maximal_steps = *steps_to_entrypoint - optimized_entry_steps;
			break_on.on_cseg_outside_analysis = 1;
			break_on.command_mask = 0;
			steps += execute(&optimized_entry_state, 1, 0, break_on, 0, 0, &tmp_accesses, 1);
			if (*steps_to_entrypoint <= optimized_entry_steps + steps) {
				// entry point found!
				break;
			}
			break_on.maximal_steps = *steps_to_entrypoint - optimized_entry_steps - steps;
			break_on.on_cseg_outside_analysis = 0;
			break_on.command_mask = MALBOLGE_JMP;
			steps += execute(&optimized_entry_state, 1, 0, break_on, 0, 0, 0, 0);
			optimized_entry_steps += steps;
			steps = 0;
			break_on.maximal_steps = 1;
			break_on.on_cseg_outside_analysis = 0;
			break_on.command_mask = 0;
			steps += execute(&optimized_entry_state, 1, 0, break_on, 0, 0, 0, 0);
		}while(1);
		free_access_analysis(&tmp_accesses);

		printf(" done.\n");

		// update accesses and entry_state if necessary...
		if (optimized_entry_steps < *steps_to_entrypoint) {
			printf("Earlier entry point found at step %d.\n",optimized_entry_steps);
			printf("Malbolge disassembler is updating memory access information for the new\nentry point. Please wait...");
			fflush(stdout);
			// update acces information
			// at first: go to new entry point
			copy_state(&optimized_entry_state,initial_state);
			break_on.maximal_steps = optimized_entry_steps;
			break_on.on_cseg_outside_analysis = 0;
			break_on.command_mask = 0;
			execute(&optimized_entry_state, 1, 0, break_on, 0, 0, 0, 0);
			// now update access information starting here
			copy_state(entry_state,&optimized_entry_state);
			break_on.maximal_steps = *steps_to_entrypoint - optimized_entry_steps + 1; // +1: the JMP at the old entry point has to be added!
			break_on.on_cseg_outside_analysis = 0;
			break_on.command_mask = 0;
			execute(&optimized_entry_state, 1, 0, break_on, 0, 0, accesses, 0);
			accesses->maximal_steps_from_entry_point += *steps_to_entrypoint - optimized_entry_steps; // update maximal user-steps from entrypoint
			*steps_to_entrypoint = optimized_entry_steps;
			printf(" done.\n");
		}else{
			printf("No better entry point has been found.\n");
		}
	}else{
		printf("The entry point seems to be optimal.\n");
	}
	return 0;
}



int extract_codeblocks(struct ConnectedMemoryCells** creg_components, struct ConnectedMemoryCells** dreg_components,
		struct AccessAnalysis* accesses, const struct VMState* entry_state) {

	struct BreakCondition break_on;
	
	if (!creg_components || !dreg_components || !accesses) {
		return 1;
	}
	
	// run over accesses-fields:
	//int* dreg_movd_destinations;
	//int* dreg_jmp_destinations;
	// and fix the successor's offset if the cell which points to the successor is modified during execution
	printf("Malbolge disassembler processes memory access information now.\nPlease wait...");
	fflush(stdout);
	int i;
	for (i=0;i<59049;i++) {
		if ((accesses->memory[i].access & DREG_ACCESS_RW) && (accesses->memory[i].access & (DREG_ACCESS_JUMP | DREG_ACCESS_MOVD))) {
			// follow dreg_movd_destinations, dreg_jmp_destinations and set FIXED_OFFSET there.
			if (accesses->memory[i].dreg_movd_destinations) {
				struct avl_traverser it;
				avl_t_init(&it, accesses->memory[i].dreg_movd_destinations);
				int* movd_dest;
				while ((movd_dest = (int*)avl_t_next(&it))) {
					accesses->memory[*movd_dest+1].access |= FIXED_OFFSET;
				}
			}
			if (accesses->memory[i].dreg_jmp_destinations) {
				struct avl_traverser it;
				avl_t_init(&it, accesses->memory[i].dreg_jmp_destinations);
				int* jmp_dest;
				while ((jmp_dest = (int*)avl_t_next(&it))) {
					accesses->memory[*jmp_dest+1].access |= FIXED_OFFSET;
				}
			}
		}
	}
	// find out whether A register at entry point position matters (called OUT or OPR before IN, ROT, HLT).
	// therefore: run through program until OUT, OPR, IN, ROT, HLT
	// use accesses->maximal_steps_from_entry_point to prevent hanging in (senseless) endless-loops
	// not necessary at the moment, because entry-point guarantees IN or OUT operation.
	// But if the entry point-detection is changed, this makes sure that endless loops will not occur here.
	accesses->a_register_matters = 0;
	VMState tmp_state;
	copy_state(&tmp_state,entry_state);
	break_on.maximal_steps = accesses->maximal_steps_from_entry_point;
	break_on.on_cseg_outside_analysis = 0;
	break_on.command_mask = MALBOLGE_HLT | MALBOLGE_OPR | MALBOLGE_OUT | MALBOLGE_IN | MALBOLGE_ROT;
	execute(&tmp_state, 0, 0, break_on, 0, 0, 0, 0);
	// check whether tmp_state.c points to OUT or OPR.
	if (tmp_state.memory[tmp_state.c] >= 33 && tmp_state.memory[tmp_state.c] <= 126 &&
			((tmp_state.memory[tmp_state.c]+tmp_state.c)%94 == 5 || (tmp_state.memory[tmp_state.c]+tmp_state.c)%94 == 62)) {
		// the A register matters
		accesses->a_register_matters = 1;
	}

	// go through access.memory-array and find conneted blocks


	// extract and store memory cells ever used
	struct avl_table* ever_used_memory_cells = avl_create(compare_integer, 0, &avl_allocator_default);
	if (!ever_used_memory_cells) {
		fprintf(stderr,"Cannot allocate memory.\n");
		return 1;
	}
	// fill ever_used_memory_cells according to AccessAnalysis.
	for (i=0;i<59049;i++) {
		if (accesses->memory[i].access) {
			int* cell_id = (int*)malloc(sizeof(int));
			if (!cell_id) {
				fprintf(stderr,"Cannot allocate memory.\n");
				return 1;
			}
			*cell_id = i;
			avl_insert(ever_used_memory_cells, cell_id);
		}
	}

	*creg_components = (struct ConnectedMemoryCells*)malloc(sizeof(struct ConnectedMemoryCells)); // zero-terminated
	*dreg_components = (struct ConnectedMemoryCells*)malloc(sizeof(struct ConnectedMemoryCells)); // zero-terminated
	int number_creg_components = 0; // to avoid counting its size again and again
	int number_dreg_components = 0; // to avoid counting its size again and again
	if (!*creg_components || !*dreg_components) {
		fprintf(stderr,"Cannot allocate memory.\n");
		return 1;
	}
	memset(*creg_components,0,sizeof(struct ConnectedMemoryCells));
	memset(*dreg_components,0,sizeof(struct ConnectedMemoryCells));

	// while ever_used_memory_cells is no empty
	while (ever_used_memory_cells->avl_count != 0) {
		//take first cell and build a new connected memory block:
		struct avl_traverser it;
		//avl_t_init(&it, ever_used_memory_cells);
		int* first_cell = (int*)avl_t_first(&it, ever_used_memory_cells);
		if (!first_cell) {
			fprintf(stderr,"Error accessing AVL tree.\n");
			return 1;
		}
		// initialize new connected memory block
		struct ConnectedMemoryCells current_memory_block;
		memset(&current_memory_block, 0, sizeof(ConnectedMemoryCells));
		current_memory_block.cells = avl_create(compare_integer, 0, &avl_allocator_default);
		if (!current_memory_block.cells) {
			fprintf(stderr,"Cannot allocate memory.\n");
			return 1;
		}
		// list of elements to be added in future
		struct avl_table* cells_to_be_added = avl_create(compare_integer, 0, &avl_allocator_default);
		if (!cells_to_be_added) {
			fprintf(stderr,"Cannot allocate memory.\n");
			return 1;
		}
		// first_cell should be added to current memory block, then it need not be processed for further blocks
		avl_insert(cells_to_be_added, first_cell);
		avl_delete(ever_used_memory_cells, first_cell);
		while (cells_to_be_added->avl_count != 0) {
			//take first cell of cells_to_be_added
			//avl_t_init(&it, cells_to_be_added);
			int* add_cell = (int*)avl_t_first(&it, cells_to_be_added);
			if (!add_cell) {
				fprintf(stderr,"Error accessing AVL tree.\n");
				return 1;
			}
			// find all successors and predecessors,
			//		add them to cells_to_be_added (if not added to any memory block yet), remove them from ever_used_memory_cells
			if (accesses->memory[*add_cell].access & CREG_REACHED_WO_JMP) {
				// add preceeding cell to cells_to_be_added, delete it from ever_used_memory_cells
				int prec = (*add_cell) - 1;
				if (prec < 0) {
					// underflow; offsets should be fixed.
					// note that fixing offsets is ot necessary due to the malbolge program itself
					// but the way the .CODE or .DATA section will be printed out later requires
					// fixed offsets to work. otherwse the connected component would break.
					current_memory_block.fixed_offset = 1;
					prec = 59048;
				}
				void* tmp = avl_delete(ever_used_memory_cells,&prec);
				if (tmp) {
					avl_insert(cells_to_be_added, tmp);
				}
			}
			if (accesses->memory[*add_cell].access & CREG_TRANSLATED) {
				// add succeeding cell to cells_to_be_added, delete it from ever_used_memory_cells
				int succ = (*add_cell) + 1;
				if (succ > 59048) {
					// overflow; offsets should be fixed. (see above)
					current_memory_block.fixed_offset = 1;
					succ = 0;
				}
				void* tmp = avl_delete(ever_used_memory_cells,&succ);
				if (tmp) {
					avl_insert(cells_to_be_added, tmp);
				}
			}
			// go through dreg_successors_normal_flow
			if (accesses->memory[*add_cell].dreg_successors_normal_flow) {
				avl_t_init(&it, accesses->memory[*add_cell].dreg_successors_normal_flow);
				void* cell = 0;
				while ((cell = avl_t_next(&it))) {
					if (*((int*)cell) < *add_cell) {
						// overflow; offsets should be fixed. (see above)
						current_memory_block.fixed_offset = 1;
					}
					void* tmp = avl_delete(ever_used_memory_cells,cell);
					if (tmp) {
						avl_insert(cells_to_be_added, tmp);
					}
				}
			}
			// go through dreg_predecessors_normal_flow
			if (accesses->memory[*add_cell].dreg_predecessors_normal_flow) {
				avl_t_init(&it, accesses->memory[*add_cell].dreg_predecessors_normal_flow);
				void* cell = 0;
				while ((cell = avl_t_next(&it))) {
					if (*((int*)cell) > *add_cell) {
						// underflow; offsets should be fixed. (see above)
						current_memory_block.fixed_offset = 1;
					}
					void* tmp = avl_delete(ever_used_memory_cells,cell);
					if (tmp) {
						avl_insert(cells_to_be_added, tmp);
					}
				}
			}

			//add first cell to current_memory_block, update current_memory_block's flags etc., delete cell from cells_to_be_added
			if (accesses->memory[*add_cell].access & (CREG_TRANSLATED | CREG_REACHED_WO_JMP | CREG_EXECUTED | CREG_REACHED_BY_JMP)) {
				// set CREG-Flag in current connected block
				current_memory_block.codesection = 1;
			}
			if (accesses->memory[*add_cell].access & (DREG_ACCESS_MOVD | DREG_ACCESS_JUMP | DREG_ACCESS_RW | DREG_REACHED_BY_MOVD)) {
				// set DREG-Flag in current connected block
				current_memory_block.datasection = 1;
			}
			if (accesses->memory[*add_cell].access & FIXED_OFFSET) {
				// set FIXED_OFFSET-Flag in current connected block
				current_memory_block.fixed_offset = 1;
			}

			avl_delete(cells_to_be_added, add_cell);
			avl_insert(current_memory_block.cells, add_cell);
		}
		//check whether memory_block is a creg or dreg element;
		if (current_memory_block.datasection && current_memory_block.codesection) {
			// if not unique, use it inside data-section (more flexible), but with fixed offset
			current_memory_block.codesection = 0;
			current_memory_block.fixed_offset = 1;
		}
		//add current_memory_block to creg_components or dreg_components;
		if (current_memory_block.datasection) {
			// add to datasection
			struct ConnectedMemoryCells* tmp = (struct ConnectedMemoryCells*)realloc(
					*dreg_components, sizeof(struct ConnectedMemoryCells)*(number_dreg_components+2)); // zero-terminated
			if (!tmp) {
				fprintf(stderr,"Cannot allocate memory.\n");
				return 1;
			}
			*dreg_components = tmp;
			memcpy(*dreg_components+number_dreg_components, &current_memory_block, sizeof(struct ConnectedMemoryCells));
			number_dreg_components++;
			memset(*dreg_components+number_dreg_components,0,sizeof(struct ConnectedMemoryCells));
		} else if (current_memory_block.codesection) {
			// add to codesection
			struct ConnectedMemoryCells* tmp = (struct ConnectedMemoryCells*)realloc(
					*creg_components, sizeof(struct ConnectedMemoryCells)*(number_creg_components+2)); // zero-terminated
			if (!tmp) {
				fprintf(stderr,"Cannot allocate memory.\n");
				return 1;
			}
			*creg_components = tmp;
			memcpy(*creg_components+number_creg_components, &current_memory_block, sizeof(struct ConnectedMemoryCells));
			number_creg_components++;
			memset(*creg_components+number_creg_components,0,sizeof(struct ConnectedMemoryCells));
		} else {
			// why were current_memory_block's cells ever added to ever_used_index?
			fprintf(stderr,"Warning: Internal error occured. Output may be incorrect or even invalid.\n");
		}
	}
	// done.
	printf(" done.\n");
	return 0;
}


void add_dreg_normal_successor(struct AccessAnalysis* accesses, int cell, int successor) {
	if (!accesses) {
		return;
	}
	if (cell < 0 || cell >= 59049 || successor < 0 || successor >= 59049) {
		return;
	}

	if (accesses->memory[cell].dreg_successors_normal_flow == 0) {
		accesses->memory[cell].dreg_successors_normal_flow = avl_create(compare_integer, 0, &avl_allocator_default);
	}
	if (accesses->memory[cell].dreg_successors_normal_flow == 0) {
		printf("\n");
		fprintf(stderr,"Error: Cannot allocate memory.\n");
		exit(1);
	}
	int* succ = (int*)malloc(sizeof(int));
	if (succ == 0) {
		printf("\n");
		fprintf(stderr,"Error: Cannot allocate memory.\n");
		exit(1);
	}
	*succ = successor;
	int* old = avl_insert(accesses->memory[cell].dreg_successors_normal_flow, succ);
	if (old) {
		free(succ);
	}
}


void add_dreg_normal_predecessors(struct AccessAnalysis* accesses, int cell, int predecessor) {
	if (!accesses) {
		return;
	}
	if (cell < 0 || cell >= 59049 || predecessor < 0 || predecessor >= 59049) {
		return;
	}

	if (accesses->memory[cell].dreg_predecessors_normal_flow == 0) {
		accesses->memory[cell].dreg_predecessors_normal_flow = avl_create(compare_integer, 0, &avl_allocator_default);
	}
	if (accesses->memory[cell].dreg_predecessors_normal_flow == 0) {
		printf("\n");
		fprintf(stderr,"Error: Cannot allocate memory.\n");
		exit(1);
	}
	int* pred = (int*)malloc(sizeof(int));
	if (pred == 0) {
		printf("\n");
		fprintf(stderr,"Error: Cannot allocate memory.\n");
		exit(1);
	}
	*pred = predecessor;
	int* old = avl_insert(accesses->memory[cell].dreg_predecessors_normal_flow, pred);
	if (old) {
		free(pred);
	}
}



void add_jmp_destination(struct AccessAnalysis* accesses, int cell, int destination) {
	if (!accesses) {
		return;
	}
	if (cell < 0 || cell >= 59049 || destination < 0 || destination >= 59049) {
		return;
	}

	if (accesses->memory[cell].dreg_jmp_destinations == 0) {
		accesses->memory[cell].dreg_jmp_destinations = avl_create(compare_integer, 0, &avl_allocator_default);
	}
	if (accesses->memory[cell].dreg_jmp_destinations == 0) {
		printf("\n");
		fprintf(stderr,"Error: Cannot allocate memory.\n");
		exit(1);
	}
	int* dest = (int*)malloc(sizeof(int));
	if (dest == 0) {
		printf("\n");
		fprintf(stderr,"Error: Cannot allocate memory.\n");
		exit(1);
	}
	*dest = destination;
	int* old = avl_insert(accesses->memory[cell].dreg_jmp_destinations, dest);
	if (old) {
		free(dest);
	}
}

void add_movd_destination(struct AccessAnalysis* accesses, int cell, int destination) {
	if (!accesses) {
		return;
	}
	if (cell < 0 || cell >= 59049 || destination < 0 || destination >= 59049) {
		return;
	}

	if (accesses->memory[cell].dreg_movd_destinations == 0) {
		accesses->memory[cell].dreg_movd_destinations = avl_create(compare_integer, 0, &avl_allocator_default);
	}
	if (accesses->memory[cell].dreg_movd_destinations == 0) {
		printf("\n");
		fprintf(stderr,"Error: Cannot allocate memory.\n");
		exit(1);
	}
	int* dest = (int*)malloc(sizeof(int));
	if (dest == 0) {
		printf("\n");
		fprintf(stderr,"Error: Cannot allocate memory.\n");
		exit(1);
	}
	*dest = destination;
	int* old = avl_insert(accesses->memory[cell].dreg_movd_destinations, dest);
	if (old) {
		free(dest);
	}
}

int execute(struct VMState* state, int interactive, struct UserInput* input, struct BreakCondition break_on, int* last_jmp, int* interrupted, struct AccessAnalysis* accesses, int access_analysis_ro) {

	int steps = 0;
	int input_pos = 0;
	int last_accessed_d_pos = -1;

	if (last_jmp)
		*last_jmp = 0;
	if (interrupted)
		*interrupted = 0;
	if (state == 0)
		return 0;

	if (interactive && input) {
		input->length = 0;
		input->input  = 0;
	}

	got_sigint();

	while (1) {
		if (got_sigint()) {
			if (interrupted)
				*interrupted = 1;
			return steps;
		}
		if (break_on.maximal_steps > 0 && steps >= break_on.maximal_steps) {
			return steps;
		}
		if (break_on.on_cseg_outside_analysis > 0 && accesses) {
			if (!(accesses->memory[state->c].access & CREG_EXECUTED)) {
				return steps;
			}
		}
		unsigned int instruction = state->memory[state->c];
		if (instruction < 33 || instruction > 126) {
			if (interactive) {
				fprintf(stderr, "Invalid command 0x%05x at 0x%05x.\n",instruction,state->c);
			}
			// TODO: maybe only give warning message and continue...?
			return steps;
		}
		instruction = (instruction+state->c)%94;
		if (accesses && steps && !access_analysis_ro) { // don't add very first JMP-command at entry-point here...
			accesses->memory[state->c].access |= CREG_EXECUTED;
		}

		switch (instruction){
			case 4:
				// JMP
				if (break_on.command_mask & MALBOLGE_JMP) {
					return steps;
				}

				if (accesses && !access_analysis_ro) {
					accesses->memory[state->d].access |= DREG_ACCESS_JUMP;
					add_jmp_destination(accesses, state->d, state->memory[state->d]);
					accesses->memory[state->memory[state->d]+1].access |= CREG_REACHED_BY_JMP;

					if (last_accessed_d_pos != -1) {
						add_dreg_normal_successor(accesses, last_accessed_d_pos, state->d);
						add_dreg_normal_predecessors(accesses, state->d, last_accessed_d_pos);
					}
					last_accessed_d_pos = state->d;
				}

				state->c = state->memory[state->d];
				if (last_jmp)
					*last_jmp = steps;
				break;
			case 5:
				// OUT
				if (break_on.command_mask & MALBOLGE_OUT) {
					return steps;
				}
				if (interactive) {
					printf("%c",(char)(state->a));
				}
				break;
			case 23:
				// IN
				if (break_on.command_mask & MALBOLGE_IN) {
					return steps;
				}
				if (interactive) {
					int read = getchar();
					if (read == EOF) {
						if (feof(stdin)) {
							state->a = 59048;
						} else {
							// error or interrupt occured while reading stdin
							// printf("ERROR");
							got_sigint(); // maybe failed due to SIGINT, so reset SIGINT
							if (interrupted)
								*interrupted = 1;
							return steps;
						}
					} else {
						state->a = read;
					}
					// store input
					if (input) {
						if (!input->input) {
							input->input = (int*)malloc(sizeof(int)*1);
							if (input->input) {
								input->input[0] = read;
								input_pos = 1;
								input->length = input_pos;
							}
						} else {
							int* tmp = (int*)realloc(input->input, sizeof(int)*(input_pos+1));
							if (tmp) {
								input->input = tmp;
								input->input[input_pos] = read;
								input_pos++;
								input->length = input_pos;
							}
						}
					}
				}else{
					// read from input
					if (input) {
						if (input->input && input->length > input_pos) {
							state->a = input->input[input_pos];
							input_pos++;
						} else {
							// error or interrupt occured while reading stdin
							// printf("ERROR");
							return steps;
						}
					} else {
						// error or interrupt occured while reading stdin
						// printf("ERROR");
						return steps;
					}
				}
				break;
			case 39:
				// ROT
				if (break_on.command_mask & MALBOLGE_ROT) {
					return steps;
				}

				if (break_on.on_cseg_outside_analysis > 0 && accesses) {
					if ((accesses->memory[state->d].access & CREG_EXECUTED) && !(accesses->memory[state->d].access & DREG_ACCESS_RW)) {
						return steps;
					}
				}

				if (accesses && !access_analysis_ro) {
					accesses->memory[state->d].access |= DREG_ACCESS_RW;

					if (last_accessed_d_pos != -1) {
						add_dreg_normal_successor(accesses, last_accessed_d_pos, state->d);
						add_dreg_normal_predecessors(accesses, state->d, last_accessed_d_pos);
					}
					last_accessed_d_pos = state->d;
				}

				state->a = (state->memory[state->d] = rotate_r(state->memory[state->d]));
				break;
			case 40:
				// MOV
				if (break_on.command_mask & MALBOLGE_MOV) {
					return steps;
				}

				if (accesses && !access_analysis_ro) {
					accesses->memory[state->d].access |= DREG_ACCESS_MOVD;
					add_movd_destination(accesses, state->d, state->memory[state->d]);
					accesses->memory[state->memory[state->d]+1].access |= DREG_REACHED_BY_MOVD;
					if (last_accessed_d_pos != -1) {
						add_dreg_normal_successor(accesses, last_accessed_d_pos, state->d);
						add_dreg_normal_predecessors(accesses, state->d, last_accessed_d_pos);
					}
					last_accessed_d_pos = state->memory[state->d]+1; //movd -> use movd-destination as origin...
				}

				state->d = state->memory[state->d];
				break;
			case 62:
				// OPR
				if (break_on.command_mask & MALBOLGE_OPR) {
					return steps;
				}

				if (break_on.on_cseg_outside_analysis > 0 && accesses) {
					if ((accesses->memory[state->d].access & CREG_EXECUTED) && !(accesses->memory[state->d].access & DREG_ACCESS_RW)) {
						return steps;
					}
				}

				if (accesses && !access_analysis_ro) {
					accesses->memory[state->d].access |= DREG_ACCESS_RW;

					if (last_accessed_d_pos != -1) {
						add_dreg_normal_successor(accesses, last_accessed_d_pos, state->d);
						add_dreg_normal_predecessors(accesses, state->d, last_accessed_d_pos);
					}
					last_accessed_d_pos = state->d;
				}

				state->a = (state->memory[state->d] = crazy(state->a, state->memory[state->d]));
				break;
			case 81:
				// HLT
				if (break_on.command_mask & MALBOLGE_HLT) {
					return steps;
				}
				return steps+1;
			case 68:
			default:
				// NOP
				if (break_on.command_mask & MALBOLGE_NOP) {
					return steps;
				}
				break;
		}
		// if memory[c] has been modified by the command above, bring it back into valid range
		// note that the original interpreter would crash in this case
		// TODO: maybe give warning message if memory[c] lies outside valid range
		if (state->memory[state->c] < 33)
			state->memory[state->c] += 94;
		state->memory[state->c]-=33;
		if (state->memory[state->c] > 93)
			state->memory[state->c] %= 94;
		// encrypt command
		state->memory[state->c] = translation[state->memory[state->c]];

		if (accesses && !access_analysis_ro) {
			accesses->memory[state->c].access |= CREG_TRANSLATED;
		}

		state->c = (state->c+1)%59049;

		if (accesses && !access_analysis_ro) {
			accesses->memory[state->c].access |= CREG_REACHED_WO_JMP;
		}

		state->d = (state->d+1)%59049;
		steps++;
	}
}


void copy_state(struct VMState* dest, const struct VMState* src) {
	if (src == 0 || dest == 0)
		return;
	dest->a = src->a;
	dest->c = src->c;
	dest->d = src->d;
	memcpy(dest->memory, src->memory, sizeof(int)*59060);
}



void sigint_handler(int s) {
	//printf("got sigint\n");
	sigint_store++;
}
int got_sigint() {
	if (sigint_store > 0) {
		sigint_store = 0;
		return 1;
	}
	return 0;
}

void copy_access_analysis(struct AccessAnalysis* dest, struct AccessAnalysis* src) {
	if (src == 0 || dest == 0) {
		return;
	}
	memcpy(dest->memory, src->memory, sizeof(src->memory));
	// TODO: copy allocations recursive!!!
}

void free_access_analysis(struct AccessAnalysis* access) {
	// TODO
	// recursive allocations; not the root
}
