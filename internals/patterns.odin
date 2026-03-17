package internals

// ------------- FUNDAMENTAL PATTERNS -----------------------------------------------------

// XX:
//   -> e
//   <- e, ee, s, es
//   -> s, se
@(rodata)
PATTERN_XX : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e},
        {.e, .ee, .s, .es},
        {.s, .se}
    }
}
// NK:
//   <- s
//   ...
//   -> e, es
//   <- e, ee
@(rodata)
PATTERN_NK : MessagePattern = {
    pre_messages = {.res_s},
    messages = {
        {.e, .es},
        {.e, .ee},
    }
}
// NN:
//   -> e
//   <- e, ee
@(rodata)
PATTERN_NN : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e, .ee},
    }
}
// KN:
//   -> s
//   ...
//   -> e
//   <- e, ee, se
@(rodata)
PATTERN_KN : MessagePattern = {
    pre_messages = {.ini_s},
    messages = {
        {.e,},
        {.e, .ee, .se}
    }
}
// KK:
//   -> s
//   <- s
//   ...
//   -> e, es, ss
//   <- e, ee, se
@(rodata)
PATTERN_KK : MessagePattern = {
    pre_messages = {.ini_s, .res_s},
    messages = {
        {.e, .es, .ss},
        {.e, .ee, .se},
    }
}
// NX:
//   -> e
//   <- e, ee, s, es
@(rodata)
PATTERN_NX : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e},
        {.e, .ee, .s, .es},
    }
}
// KX:
//   -> s
//   ...
//   -> e
//   <- e, ee, se, s, es
@(rodata)
PATTERN_KX : MessagePattern = {
    pre_messages = {.ini_s},
    messages = {
        {.e},
        {.e, .ee, .se, .s, .es}
    }
}
// XN:
//   -> e
//   <- e, ee
//   -> s, se
@(rodata)
PATTERN_XN : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e},
        {.e, .ee},
        {.s, .se},
    }
}
// IN:
//   -> e, s
//   <- e, ee, se
@(rodata)
PATTERN_IN : MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e, .s},
        {.e, .ee, .se},
    }
}
// XK:
//   <- s
//   ...
//   -> e, es
//   <- e, ee
//   -> s, se
@(rodata)
PATTERN_XK : MessagePattern = {
    pre_messages = {.res_s},
    messages = {
        {.e, .es},
        {.e, .ee},
        {.s, .se},
    }
}
// IK:
//   <- s
//   ...
//   -> e, es, s, ss
//   <- e, ee, se
@(rodata)
PATTERN_IK : MessagePattern = {
    pre_messages = {.res_s}, 
    messages = {
        {.e, .es, .s, .ss},
        {.e, .ee, .se}
    }
}
// IX:
//   -> e, s
//   <- e, ee, se, s, es
@(rodata)
PATTERN_IX :  MessagePattern = {
    pre_messages = nil,
    messages = {
        {.e, .s},
        {.e, .ee, .se, .s, .es},
    }
}

// ----------------------------------------------------------------------------------------