tmux new-session -s mysession -d
tmux split-window -v -t mysession:0
tmux split-window -h -t mysession:0.1
tmux split-window -h -t mysession:0.0
tmux attach -t mysession
