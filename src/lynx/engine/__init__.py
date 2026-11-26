"""The LangGraph run graph: estimate, prepare, map, investigate, prove, report, fix.

Modules: graph (the compiled run graph and its checkpointer), state (RunState and
its reducers), and nodes/ (one module per stage). Prepare and report are built; the
other stages arrive in later phases.
"""
