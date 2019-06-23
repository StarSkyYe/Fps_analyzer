import Fps_analyzer

def main():
    while True:
        pcap_file_path = input("Please input your pcap file path: ")
        fps_analyzer = Fps_analyzer.Fps_analyzer()
        fps_analyzer.process_fps_from_file(pcap_file_path)
        print(fps_analyzer.format_fps())

        print("\n")
        go_on = input("Will you like to continue? (yes): ")
        if go_on == None or go_on == "" or go_on.lower() == "yes":
            continue
        else:
            break

if __name__ == '__main__':
    main()