struct field {                                                                                                               
    int b[8];                                                                                                                
};                                                                                                                           
                                                                                                                             
struct buffer {                                                                                                              
    struct field a;                                                                                                          
    int x;                                                                                                                   
};                                                                                                                           
                                                                                                                             
int main(int argc, char* argv[])                                                                                             
{                                                                                                                            
    struct buffer b1;                                                                                                        
    int i;                                                                                                                   
                                                                                                                             
    b1.a.b[10] = 1;                                                                                                          
                                                                                                                             
    return 42;                                                                                                               
}                                                                                                                            
                                                                                                                          
/*
 * check-name: Check array overflow
 * check-command: smatch sm_overflow.c
 *
 * check-output-start
sm_overflow.c:15 main() error: buffer overflow 'b1.a.b' 8 <= 10
 * check-output-end
 */
