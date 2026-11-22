#ifndef KEYGATE_POLICY_H
#define KEYGATE_POLICY_H

#ifdef __cplusplus
extern "C" {
#endif

const char *keygate_policy_version(void);
char *keygate_policy_evaluate(const char *request_json, const char *config_json);
void keygate_policy_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif
